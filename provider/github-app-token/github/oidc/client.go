package oidc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

const (
	// The value of User-Agent header
	httpUserAgent = "actions-github-token/1.0"
)

// Doer is a interface for doing an http request.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	httpClient  Doer
	issuer      string
	thumbprints [][]byte
}

func NewClient(httpClient Doer, issuer string, thumbprints []string) (*Client, error) {
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html
	// decode thumbprints
	decoded := make([][]byte, 0, len(thumbprints))
	for _, thumb := range thumbprints {
		data, err := hex.DecodeString(thumb)
		if err != nil {
			return nil, fmt.Errorf("oidc: failed to parse thumbprints: %w", err)
		}
		decoded = append(decoded, data)
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		httpClient:  httpClient,
		issuer:      issuer,
		thumbprints: decoded,
	}, nil
}

func (c *Client) ParseWithClaims(ctx context.Context, tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
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
		key, ok := keys.Find(kid)
		if !ok {
			return nil, errors.New("oidc: key is not found")
		}
		return key.PublicKey(), nil
	})
}
