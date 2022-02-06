package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github/jwk"
)

func (c *Client) GetJWKS(ctx context.Context, url string) (*jwk.Set, error) {
	return c.jwks.Do(ctx, url, func(ctx context.Context) (*jwk.Set, time.Time, error) {
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

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, time.Time{}, err
		}
		req.Header.Set("User-Agent", httpUserAgent)
		req.Header.Set("Accept", "application/jwk-set+json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, time.Time{}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, time.Time{}, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, time.Time{}, err
		}

		set, err := jwk.ParseSet(data)
		if err != nil {

		}
		return set, expiresAt, nil
	})
}
