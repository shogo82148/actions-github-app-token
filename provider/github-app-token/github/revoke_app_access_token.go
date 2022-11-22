package github

import (
	"context"
	"io"
	"net/http"
)

// RevokeAppAccessToken revokes the token.
// https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token
func (c *Client) RevokeAppAccessToken(ctx context.Context, token string) error {
	// build the request
	u := c.baseURL.JoinPath("installation", "token")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Github-Next-Global-ID", "1")

	// send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// parse the response
	if resp.StatusCode != http.StatusNoContent {
		return newErrUnexpectedStatusCode(resp)
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}
