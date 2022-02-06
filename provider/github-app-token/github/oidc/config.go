package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	prefix := strings.TrimSuffix(c.issuer, "/") // remove '/'
	configURL := prefix + "/.well-known/openid-configuration"
	return c.oidcConfig.Do(ctx, configURL, func(ctx context.Context) (*Config, time.Time, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		// some providers, such as GitHub Actions, returns "cache-control: no-store,no-cache".
		// but I think I can cache them.
		now := time.Now()
		expiresAt := now.Add(time.Hour)

		// The monotonic clock reading can be incorrect in cases where the host system is hibernated
		// (for example using EC2 Hibernate, AWS Lambda, etc).
		// So convert it to wallclock.
		expiresAt = expiresAt.Round(0)

		// build the request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
		if err != nil {
			return nil, time.Time{}, err
		}
		req.Header.Set("User-Agent", httpUserAgent)
		req.Header.Set("Accept", "application/json")

		// send the request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, time.Time{}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, time.Time{}, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
		}

		// parse the response body
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, time.Time{}, err
		}
		var config Config
		if err := json.Unmarshal(buf, &config); err != nil {
			return nil, time.Time{}, err
		}
		return &config, expiresAt, nil
	})
}
