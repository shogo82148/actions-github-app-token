package githubapptoken

import (
	"context"
	"encoding/base64"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
	"github.com/shogo82148/goat/jwt"
)

type githubClientDummy struct{}

func (c *githubClientDummy) GetApp(ctx context.Context) (*github.GetAppResponse, error) {
	return &github.GetAppResponse{
		HTMLURL: "https://github.com/shogo82148/actions-github-app-token",
	}, nil
}

func (c *githubClientDummy) GetRepo(ctx context.Context, token, owner, repo string) (*github.GetRepoResponse, error) {
	return &github.GetRepoResponse{
		ID:     398574950,
		NodeID: "R_kgDOF8HFZg",
	}, nil
}

func (c *githubClientDummy) GetReposInfo(ctx context.Context, token, nodeID string) (*github.GetReposInfoResponse, error) {
	return &github.GetReposInfoResponse{}, nil
}

func (c *githubClientDummy) GetReposContent(ctx context.Context, token, owner, repo, path string) (*github.GetReposContentResponse, error) {
	content := `
repositories:
  - R_kgDOF8HFZg
`
	return &github.GetReposContentResponse{
		Type:     "file",
		Encoding: "base64",
		Content:  base64.StdEncoding.EncodeToString([]byte(content)),
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
	return &github.ActionsIDToken{
		Claims: &jwt.Claims{
			Audience: []string{"https://github-app.shogo82148.com/1234567890"},
		},
		Repository:   "shogo82148/actions-github-app-token",
		RepositoryID: "398574950",
	}, nil
}

func (c *githubClientDummy) RevokeAppAccessToken(ctx context.Context, token string) error {
	return nil
}

func NewDummyHandler() *Handler {
	return &Handler{
		github: &githubClientDummy{},
		appID:  1234567890,
	}
}
