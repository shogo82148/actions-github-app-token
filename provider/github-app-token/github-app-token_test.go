package githubapptoken

import (
	"context"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
)

type githubClientMock struct {
	GetAppFunc               func(ctx context.Context) (*github.GetAppResponse, error)
	GetReposInstallationFunc func(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error)
	CreateAppAccessTokenFunc func(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error)
	ValidateAPIURLFunc       func(url string) error
	ParseIDTokenFunc         func(ctx context.Context, idToken string) (*github.ActionsIDToken, error)
}

func (c *githubClientMock) GetApp(ctx context.Context) (*github.GetAppResponse, error) {
	return c.GetAppFunc(ctx)
}

func (c *githubClientMock) GetReposInstallation(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error) {
	return c.GetReposInstallationFunc(ctx, owner, repo)
}

func (c *githubClientMock) CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error) {
	return c.CreateAppAccessTokenFunc(ctx, installationID, permissions)
}

func (c *githubClientMock) ValidateAPIURL(url string) error {
	return c.ValidateAPIURLFunc(url)
}

func (c *githubClientMock) ParseIDToken(ctx context.Context, idToken string) (*github.ActionsIDToken, error) {
	return c.ParseIDTokenFunc(ctx, idToken)
}

// TODO: write tests
var _ githubClientMock
