package githubapptoken

import (
	"context"
	"net/http"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
)

type githubClientDummy struct{}

func (c *githubClientDummy) CreateStatus(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error) {
	if token != "ghs_dummyGitHubToken" || owner != "shogo82148" || repo != "actions-aws-assume-role" || ref != "e3a45c6c16c1464826b36a598ff39e6cc98c4da4" {
		return nil, &github.UnexpectedStatusCodeError{StatusCode: http.StatusBadRequest}
	}
	return &github.CreateStatusResponse{
		Creator: &github.CreateStatusResponseCreator{
			Login: "github-actions[bot]",
			ID:    41898282,
			Type:  "Bot",
		},
	}, nil
}

func (c *githubClientDummy) GetReposInstallation(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error) {
	return &github.GetReposInstallationResponse{
		ID: 123456,
	}, nil
}

func (c *githubClientDummy) CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error) {
	return &github.CreateAppAccessTokenResponse{
		Token: "ghs_dummyGitHubToken",
	}, nil
}

func (c *githubClientDummy) ValidateAPIURL(url string) error {
	return nil
}

func NewDummyHandler() *Handler {
	return &Handler{
		github: &githubClientDummy{},
	}
}
