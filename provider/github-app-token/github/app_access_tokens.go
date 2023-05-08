package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

type CreateAppAccessTokenRequest struct {
	Repositories  []string `json:"repositories,omitempty"`
	RepositoryIDs []uint64 `json:"repository_ids,omitempty"`

	Permissions *CreateAppAccessTokenRequestPermissions `json:"permissions,omitempty"`
}

type CreateAppAccessTokenRequestPermissions struct {
	Actions            string `json:"actions,omitempty"`
	Checks             string `json:"checks,omitempty"`
	Contents           string `json:"contents,omitempty"`
	Deployments        string `json:"deployments,omitempty"`
	Issues             string `json:"issues,omitempty"`
	Metadata           string `json:"metadata,omitempty"`
	Packages           string `json:"packages,omitempty"`
	PullRequests       string `json:"pull_requests,omitempty"`
	RepositoryProjects string `json:"repository_projects,omitempty"`
	SecurityEvents     string `json:"security_events,omitempty"`
	Statuses           string `json:"statuses,omitempty"`
	SingleFile         string `json:"single_file,omitempty"`

	// omit other fields, we don't use them.
}

type CreateAppAccessTokenResponse struct {
	Token string `json:"token"`

	// omit other fields, we don't use them.
}

// CreateAppAccessToken creates an installation access token for the app
// https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
func (c *Client) CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *CreateAppAccessTokenRequest) (*CreateAppAccessTokenResponse, error) {
	token, err := c.generateJWT()
	if err != nil {
		return nil, err
	}

	// build the request
	u := c.baseURL.JoinPath("app", "installations", strconv.FormatUint(installationID, 10), "access_tokens")
	body, err := json.Marshal(permissions)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
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
	if resp.StatusCode != http.StatusCreated {
		return nil, newErrUnexpectedStatusCode(resp)
	}

	var ret *CreateAppAccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
}
