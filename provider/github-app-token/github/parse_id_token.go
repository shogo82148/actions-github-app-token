package github

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type ActionsIDToken struct {
	jwt.StandardClaims
	Ref             string `json:"ref"`
	SHA             string `json:"sha"`
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	RunID           string `json:"run_id"`
	RunNumber       string `json:"run_number"`
	RunAttempt      string `json:"run_attempt"`
	Actor           string `json:"actor"`
	Workflow        string `json:"workflow"`
	HeadRef         string `json:"head_ref"`
	BaseRef         string `json:"base_ref"`
	EventName       string `json:"event_name"`
	EventType       string `json:"branch"`
	JobWorkflowRef  string `json:"job_workflow_ref"`
	Environment     string `json:"environment"`
}

type openIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
}

type jwkSet struct {
	Keys []*jwkParams `json:"keys"`
}

type jwkParams struct {
	ID        string `json:"kid"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use,omitempty"`

	X509CertificateChain [][]byte `json:"x5c,omitempty"`
	X509CertificateSHA1  string   `json:"x5t,omitempty"`

	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

func (c *Client) ParseIDToken(ctx context.Context, idToken string) (*ActionsIDToken, error) {
	var claims ActionsIDToken
	_, err := jwt.ParseWithClaims(idToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return c.findOIDCKey(ctx, token)
	})
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func (c *Client) findOIDCKey(ctx context.Context, token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
	}
	claims := token.Claims.(*ActionsIDToken)
	if claims.Issuer != c.issuer {
		return nil, fmt.Errorf("unexpected issuer: %q", claims.Issuer)
	}
	config, err := c.getOpenIDConfiguration(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get open id configuration: %w", err)
	}
	keys, err := c.getJWKS(ctx, config.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get jwks: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("kid is not found in the jwt header")
	}
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("key is not found: %q", kid)
	}
	return key, nil
}

func (c *Client) getOpenIDConfiguration(ctx context.Context) (*openIDConfiguration, error) {
	// TODO: need to cache?
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newErrUnexpectedStatusCode(resp)
	}

	var config openIDConfiguration
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *Client) getJWKS(ctx context.Context, url string) (map[string]*rsa.PublicKey, error) {
	// TODO: need to cache?
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", githubUserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// verify the certificate
	if resp.TLS == nil {
		return nil, errors.New("getting jwks must use encrypted")
	}
	if certs := resp.TLS.PeerCertificates; len(certs) > 0 {
		cert := certs[len(certs)-1]
		sum := sha1.Sum(cert.Raw)
		thumbprint := hex.EncodeToString(sum[:])
		found := false
		for _, want := range c.thumbprints {
			if strings.EqualFold(thumbprint, want) {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("got invalid certificate during getting jwks")
		}
	} else {
		return nil, errors.New("getting jwks must use encrypted")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newErrUnexpectedStatusCode(resp)
	}

	var keys jwkSet
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&keys); err != nil {
		return nil, err
	}

	result := map[string]*rsa.PublicKey{}
	for _, key := range keys.Keys {
		if key.KeyType != "RSA" {
			// TODO: support other key types?
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("failed to parse e param in jwks: %w", err)
		}
		var ev int
		for _, v := range e {
			ev = (ev << 8) | int(v)
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("failed to parse n param in jwks: %w", err)
		}
		var nv big.Int
		nv.SetBytes(n)
		result[key.ID] = &rsa.PublicKey{
			E: ev,
			N: &nv,
		}
	}
	return result, nil
}
