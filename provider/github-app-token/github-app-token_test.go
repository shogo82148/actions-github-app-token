package githubapptoken

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
	"github.com/shogo82148/goat/jwt"
)

type githubClientMock struct {
	GetAppFunc               func(ctx context.Context) (*github.GetAppResponse, error)
	GetReposInstallationFunc func(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error)
	GetRepoFunc              func(ctx context.Context, token, owner, repo string) (*github.GetRepoResponse, error)
	GetReposInfoFunc         func(ctx context.Context, token, nodeID string) (*github.GetReposInfoResponse, error)
	GetReposContentFunc      func(ctx context.Context, token, owner, repo, path string) (*github.GetReposContentResponse, error)
	CreateAppAccessTokenFunc func(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error)
	ValidateAPIURLFunc       func(url string) error
	ParseIDTokenFunc         func(ctx context.Context, idToken string) (*github.ActionsIDToken, error)
	RevokeAppAccessTokenFunc func(ctx context.Context, token string) error
}

func (c *githubClientMock) GetApp(ctx context.Context) (*github.GetAppResponse, error) {
	return c.GetAppFunc(ctx)
}

func (c *githubClientMock) GetReposInstallation(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error) {
	return c.GetReposInstallationFunc(ctx, owner, repo)
}

func (c *githubClientMock) GetRepo(ctx context.Context, token, owner, repo string) (*github.GetRepoResponse, error) {
	return c.GetRepoFunc(ctx, token, owner, repo)
}

func (c *githubClientMock) GetReposInfo(ctx context.Context, token, nodeID string) (*github.GetReposInfoResponse, error) {
	return c.GetReposInfoFunc(ctx, token, nodeID)
}

func (c *githubClientMock) GetReposContent(ctx context.Context, token, owner, repo, path string) (*github.GetReposContentResponse, error) {
	return c.GetReposContentFunc(ctx, token, owner, repo, path)
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

func (c *githubClientMock) RevokeAppAccessToken(ctx context.Context, token string) error {
	return c.RevokeAppAccessTokenFunc(ctx, token)
}

func TestHandle_Dummy(t *testing.T) {
	h := NewDummyHandler()
	_, err := h.handle(context.Background(), "dummy-token", &requestBody{
		Repositories: []string{"R_123456"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandle(t *testing.T) {
	revoked := false
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
					Repository:   "shogo82148/actions-github-app-token",
					RepositoryID: "398574950",
				}, nil
			},
			GetRepoFunc: func(ctx context.Context, token, owner, repo string) (*github.GetRepoResponse, error) {
				if token != "ghs_dummyGitHubToken" {
					t.Errorf("unexpected token: got %q, want %q", token, "ghs_dummyGitHubToken")
				}
				return &github.GetRepoResponse{
					ID:     398574950,
					NodeID: "R_kgDOF8HFZg",
				}, nil
			},
			GetReposInfoFunc: func(ctx context.Context, token, nodeID string) (*github.GetReposInfoResponse, error) {
				if token != "ghs_dummyGitHubToken" {
					t.Errorf("unexpected token: got %q, want %q", token, "ghs_dummyGitHubToken")
				}
				return &github.GetReposInfoResponse{
					ID:    398574950,
					Owner: "shogo82148",
					Name:  "actions-github-app-token",
				}, nil
			},
			GetReposContentFunc: func(ctx context.Context, token, owner, repo, path string) (*github.GetReposContentResponse, error) {
				if token != "ghs_dummyGitHubToken" {
					t.Errorf("unexpected token: got %q, want %q", token, "ghs_dummyGitHubToken")
				}
				content := "repositories:\n  - R_kgDOF8HFZg\n"
				return &github.GetReposContentResponse{
					Type:     "file",
					Encoding: "base64",
					Content:  base64.StdEncoding.EncodeToString([]byte(content)),
				}, nil
			},
			GetReposInstallationFunc: func(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error) {
				return &github.GetReposInstallationResponse{
					ID: 641323,
				}, nil
			},
			CreateAppAccessTokenFunc: func(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error) {
				return &github.CreateAppAccessTokenResponse{
					Token: "ghs_dummyGitHubToken",
				}, nil
			},
			RevokeAppAccessTokenFunc: func(ctx context.Context, token string) error {
				if token != "ghs_dummyGitHubToken" {
					t.Errorf("unexpected token: got %q, want %q", token, "ghs_dummyGitHubToken")
				}
				revoked = true
				return nil
			},
		},
		appID: 1234567890,
	}
	resp, err := h.handle(context.Background(), "dummy-token", &requestBody{
		Repositories: []string{
			"R_kgDOIeornQ", "R_kgDOIevBqQ",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GitHubToken != "ghs_dummyGitHubToken" {
		t.Errorf("unexpected token: got %q, want %q", resp.GitHubToken, "ghs_dummyGitHubToken")
	}
	if !revoked {
		t.Error("want revoked, but not")
	}
}
