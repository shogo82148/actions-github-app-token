package github

import (
	"context"
	"errors"
	"fmt"

	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/jwt"
	"github.com/shogo82148/goat/sig"
)

// GitHub's custom claims
type ActionsIDToken struct {
	*jwt.Claims
	Environment          string `jwt:"environment"`
	Ref                  string `jwt:"ref"`
	SHA                  string `jwt:"sha"`
	Repository           string `jwt:"repository"`
	RepositoryOwner      string `jwt:"repository_owner"`
	ActorID              string `jwt:"actor_id"`
	RepositoryVisibility string `jwt:"repository_visibility"`
	RepositoryID         string `jwt:"repository_id"`
	RepositoryOwnerID    string `jwt:"repository_owner_id"`
	RunID                string `jwt:"run_id"`
	RunNumber            string `jwt:"run_number"`
	RunAttempt           string `jwt:"run_attempt"`
	Actor                string `jwt:"actor"`
	Workflow             string `jwt:"workflow"`
	HeadRef              string `jwt:"head_ref"`
	BaseRef              string `jwt:"base_ref"`
	EventName            string `jwt:"event_name"`
	EventType            string `jwt:"branch"`
	RefType              string `jwt:"ref_type"`
	JobWorkflowRef       string `jwt:"job_workflow_ref"`
}

func (c *Client) ParseIDToken(ctx context.Context, idToken string) (*ActionsIDToken, error) {
	set, err := c.oidcClient.GetJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("github: failed to get JWK Set: %w", err)
	}
	token, err := jwt.Parse([]byte(idToken), jwt.FindKeyFunc(func(header *jws.Header) (key sig.SigningKey, err error) {
		jwk, ok := set.Find(header.KeyID())
		if !ok {
			return nil, fmt.Errorf("github: kid %s is not found", header.KeyID())
		}
		if jwk.Algorithm() != "" && header.Algorithm().KeyAlgorithm() != jwk.Algorithm() {
			return nil, fmt.Errorf("github: alg parameter mismatch")
		}
		key = header.Algorithm().New().NewSigningKey(jwk)
		return
	}))
	if err != nil {
		return nil, fmt.Errorf("github: failed to parse id token: %w", err)
	}
	if token.Claims.Issuer != oidcIssuer {
		return nil, errors.New("github: failed to parse id token: invalid issuer")
	}

	var claims ActionsIDToken
	if err := token.Claims.DecodeCustom(&claims); err != nil {
		return nil, fmt.Errorf("github: failed to parse id token: %w", err)
	}
	claims.Claims = token.Claims
	return &claims, nil
}
