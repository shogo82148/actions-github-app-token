package github

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type ActionsIDToken struct {
	// common jwt parameters
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`

	// GitHub's extara parameters
	Ref             string `json:"ref,omitempty"`
	SHA             string `json:"sha,omitempty"`
	Repository      string `json:"repository,omitempty"`
	RepositoryOwner string `json:"repository_owner,omitempty"`
	RunID           string `json:"run_id,omitempty"`
	RunNumber       string `json:"run_number,omitempty"`
	RunAttempt      string `json:"run_attempt,omitempty"`
	Actor           string `json:"actor,omitempty"`
	Workflow        string `json:"workflow,omitempty"`
	HeadRef         string `json:"head_ref,omitempty"`
	BaseRef         string `json:"base_ref,omitempty"`
	EventName       string `json:"event_name,omitempty"`
	EventType       string `json:"branch,omitempty"`
	JobWorkflowRef  string `json:"job_workflow_ref,omitempty"`
	Environment     string `json:"environment,omitempty"`
}

func (c *Client) ParseIDToken(ctx context.Context, idToken string) (*ActionsIDToken, error) {
	var claims ActionsIDToken
	_, err := c.oidcClient.ParseWithClaims(ctx, idToken, &claims)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func (token *ActionsIDToken) Valid() error {
	now := time.Now()

	if token.Issuer != oidcIssuer {
		return fmt.Errorf("github: unexpected issuer: %q", token.Issuer)
	}

	if token.ExpiresAt == 0 {
		return errors.New("github: the exp (expires at) parameter is not set")
	}
	truncatedTime := now.Truncate(time.Second).Unix()
	if truncatedTime >= token.ExpiresAt {
		return errors.New("github: the token is already expired")
	}

	if token.NotBefore == 0 {
		return errors.New("github: the nbf (not before) paremeter is not set")
	}

	// the not before parameter might be a future time, because GitHub rounds off it.
	// we rounds up the current time here to accept such a case.
	roundedUpTime := now.Add(time.Second - 1).Truncate(time.Second).Unix()
	if roundedUpTime < token.NotBefore {
		return errors.New("github: the token is not valid yet")
	}

	return nil
}
