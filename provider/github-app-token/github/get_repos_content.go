package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	gopath "path"
)

type GetReposContentResponse struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`

	// omit other fields, we don't use them.
}

// GetReposContent gets a repository content.
// https://docs.github.com/en/rest/repos/contents#get-repository-content
func (c *Client) GetReposContent(ctx context.Context, token, owner, repo, path string) (*GetReposContentResponse, error) {
	// build the request
	path = gopath.Clean("/" + path)
	u := c.baseURL.JoinPath("repos", url.PathEscape(owner), url.PathEscape(repo), "contents", path)
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

	var ret *GetReposContentResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
