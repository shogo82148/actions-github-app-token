package github

import (
	"context"

	"github.com/golang-jwt/jwt/v4"
)

type ActionsIDToken struct {
	jwt.StandardClaims
	Ref             string `json:"ref"`
	SHA             string `json:"sha"`
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	RunID           string `json:"run_id"`
	RunNumber       string `json:"run_number"`
	RunAttempt      string `json:"run_attempt"`
	Actor           string `json:"actor"`
	Workflow        string `json:"workflow"`
	HeadRef         string `json:"head_ref"`
	BaseRef         string `json:"base_ref"`
	EventName       string `json:"event_name"`
	EventType       string `json:"branch"`
	JobWorkflowRef  string `json:"job_workflow_ref"`
	Environment     string `json:"environment"`
}

func (c *Client) ParseIDToken(ctx context.Context, idToken string) (*ActionsIDToken, error) {
	var claims ActionsIDToken
	_, err := c.oidcClient.ParseWithClaims(ctx, idToken, &claims)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}
