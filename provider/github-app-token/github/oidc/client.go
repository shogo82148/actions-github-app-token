package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github/jwk"
	"github.com/shogo82148/memoize"
)

const (
	// The default value of User-Agent header
	defaultUserAgent = "oidc-client/1.0"
)

// Doer is a interface for doing an http request.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type ClientConfig struct {
	Doer      Doer
	Issuer    string
	UserAgent string
}

type Client struct {
	doer       Doer
	issuer     string
	userAgent  string
	oidcConfig memoize.Group[string, *Config]
	jwks       memoize.Group[string, *jwk.Set]
}

func NewClient(config *ClientConfig) (*Client, error) {
	doer := config.Doer
	if doer == nil {
		doer = http.DefaultClient
	}
	issuer := config.Issuer
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	return &Client{
		doer:      doer,
		issuer:    issuer,
		userAgent: userAgent,
	}, nil
}

func (c *Client) ParseWithClaims(ctx context.Context, tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		now := time.Now()

		// get JSON Web Key Set
		config, err := c.GetConfig(ctx)
		if err != nil {
			return nil, err
		}
		keys, err := c.GetJWKS(ctx, config.JWKSURI)
		if err != nil {
			return nil, err
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("oidc: kid of JWT is not found")
		}

		// find the key
		key, ok := keys.Find(kid)
		if !ok {
			return nil, errors.New("oidc: key is not found")
		}

		// verify the certificates
		for _, cert := range key.X509CertificateChain() {
			if now.After(cert.NotAfter) {
				return nil, errors.New("oidc: the certificate is expired")
			}
			if now.Before(cert.NotBefore) {
				return nil, errors.New("oidc: the certificate is not valid yet")
			}
		}

		// verify signing method
		publicKey := key.PublicKey()
		switch publicKey.(type) {
		case *rsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New("oidc: unexpected signing method")
			}
		case *ecdsa.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, errors.New("oidc: unexpected signing method")
			}
		case ed25519.PublicKey:
			if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, errors.New("oidc: unexpected signing method")
			}
		default:
			return nil, fmt.Errorf("oidc: unknown key type: %s", key.KeyType())
		}
		return key.PublicKey(), nil
	})
}
