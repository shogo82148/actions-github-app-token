package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type GetRepoResponse struct {
	ID     uint64 `json:"id"`
	NodeID string `json:"node_id"`
}

// GetRepo gets a repository.
// https://docs.github.com/en/rest/repos/repos#get-a-repository
func (c *Client) GetRepo(ctx context.Context, token, owner, repo string) (*GetRepoResponse, error) {
	// build the request
	u := c.baseURL.JoinPath("repos", url.PathEscape(owner), url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Github-Next-Global-ID", "1")

	// send the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// parse the response
	if resp.StatusCode != http.StatusOK {
		return nil, newErrUnexpectedStatusCode(resp)
	}

	var ret *GetRepoResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
