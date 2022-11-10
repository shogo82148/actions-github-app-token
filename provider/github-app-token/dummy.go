package githubapptoken

import (
	"context"
	"errors"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
)

type githubClientDummy struct{}

func (c *githubClientDummy) GetApp(ctx context.Context) (*github.GetAppResponse, error) {
	return &github.GetAppResponse{
		HTMLURL: "https://github.com/shogo82148/actions-github-app-token",
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

func (c *githubClientDummy) ParseIDToken(ctx context.Context, idToken string) (*github.ActionsIDToken, error) {
	return nil, errors.New("invalid jwt")
}

func NewDummyHandler() *Handler {
	return &Handler{
		github: &githubClientDummy{},
	}
}
