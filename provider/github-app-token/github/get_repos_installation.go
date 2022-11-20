package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

type GetReposInstallationResponse struct {
	ID uint64 `json:"id"`

	// omit other fields, we don't use them.
}

// GetReposInstallation gets a repository installation for the authenticated app
// https://docs.github.com/en/rest/reference/apps#get-a-repository-installation-for-the-authenticated-app
func (c *Client) GetReposInstallation(ctx context.Context, owner, repo string) (*GetReposInstallationResponse, error) {
	token, err := c.generateJWT()
	if err != nil {
		return nil, err
	}

	// build the request
	u := c.baseURL.JoinPath("repos", url.PathEscape(owner), url.PathEscape(repo), "installation")
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

	var ret *GetReposInstallationResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
