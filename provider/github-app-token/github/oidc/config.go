package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
}

// GetConfig get the OpenID Provider configuration from the issuer.
func (c *Client) GetConfig(ctx context.Context) (*Config, error) {
	// TODO: need to cache?
	prefix := strings.TrimSuffix(c.issuer, "/") // remove '/'
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prefix+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
	}

	var config Config
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
