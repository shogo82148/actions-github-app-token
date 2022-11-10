package githubapptoken

import (
	"context"
	"testing"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
	"github.com/shogo82148/goat/jwt"
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

func TestHandle(t *testing.T) {
	h := &Handler{
		github: &githubClientMock{
			ValidateAPIURLFunc: func(url string) error {
				return nil
			},
			ParseIDTokenFunc: func(ctx context.Context, idToken string) (*github.ActionsIDToken, error) {
				return &github.ActionsIDToken{
					Claims: &jwt.Claims{
						Audience: []string{"https://github-app.shogo82148.com/1234567890"},
					},
					Repository: "shogo82148/actions-github-app-token",
				}, nil
			},
			GetReposInstallationFunc: func(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error) {
				return &github.GetReposInstallationResponse{}, nil
			},
			CreateAppAccessTokenFunc: func(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error) {
				return &github.CreateAppAccessTokenResponse{
					Token: "github-app-token",
				}, nil
			},
		},
		appID: 1234567890,
	}
	resp, err := h.handle(context.Background(), "dummy-token", &requestBody{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GitHubToken != "github-app-token" {
		t.Errorf("unexpected token")
	}
}
