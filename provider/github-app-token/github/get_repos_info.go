package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

type graphqlQuery struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type GetReposInfoResponse struct {
	Owner string
	Name  string
	ID    uint64
}

type getReposInfoResponse struct {
	Data struct {
		Node struct {
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
			Name       string `json:"name"`
			DatabaseID uint64 `json:"databaseId"`
		} `json:"node"`
	} `json:"data"`
}

// GetReposContent gets a repository content.
// https://docs.github.com/en/rest/repos/contents#get-repository-content
func (c *Client) GetReposInfo(ctx context.Context, nodeID string) (*GetReposInfoResponse, error) {
	const query = `query MyQuery($id: ID!) {
node(id: $id) {
	... on Repository {
	owner {
		login
	}
	name
	databaseId
	}
}
}`

	// build the request
	payload := graphqlQuery{
		Query: query,
		Variables: map[string]any{
			"id": nodeID,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	token, err := c.generateJWT()
	if err != nil {
		return nil, err
	}
	u := c.baseURL.JoinPath("graphql")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
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

	var ret *getReposInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return &GetReposInfoResponse{
		Owner: ret.Data.Node.Owner.Login,
		Name:  ret.Data.Node.Name,
		ID:    ret.Data.Node.DatabaseID,
	}, nil
}
