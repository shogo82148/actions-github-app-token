package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github/jwk"
)

func (c *Client) GetJWKS(ctx context.Context, url string) (*jwk.Set, error) {
	// TODO: need to cache?
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "application/jwk-set+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return jwk.ParseSet(data)
}
