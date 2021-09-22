package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type GetAppResponse struct {
	HTMLURL string `json:"html_url"`

	// omit other fields, we don't use them.
}

// GetApp returns the GitHub App associated with the authentication credentials used.
// https://docs.github.com/en/rest/reference/apps#get-the-authenticated-app
func (c *Client) GetApp(ctx context.Context) (*GetAppResponse, error) {
	token, err := c.generateJWT()
	if err != nil {
		return nil, err
	}

	// build the request
	u := fmt.Sprintf("%s/app", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", githubUserAgent)
	req.Header.Set("Authorization", "Bearer "+token)

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

	var ret *GetAppResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
