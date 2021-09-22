package githubapptoken

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
)

type githubClientMock struct {
	GetAppFunc               func(ctx context.Context) (*github.GetAppResponse, error)
	CreateStatusFunc         func(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error)
	GetReposInstallationFunc func(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error)
	CreateAppAccessTokenFunc func(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error)
	ValidateAPIURLFunc       func(url string) error
	ParseIDTokenFunc         func(ctx context.Context, idToken string) (*github.ActionsIDToken, error)
}

func (c *githubClientMock) GetApp(ctx context.Context) (*github.GetAppResponse, error) {
	return c.GetAppFunc(ctx)
}

func (c *githubClientMock) CreateStatus(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error) {
	return c.CreateStatusFunc(ctx, token, owner, repo, ref, status)
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

func TestValidateGitHubToken(t *testing.T) {
	h := &Handler{
		github: &githubClientMock{
			CreateStatusFunc: func(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error) {
				if token != "ghs_dummyGitHubToken" {
					t.Errorf("unexpected GitHub Token: want %q, got %q", "ghs_dummyGitHubToken", token)
				}
				if owner != "fuller-inc" {
					t.Errorf("unexpected owner: want %q, got %q", "fuller-inc", owner)
				}
				if repo != "actions-aws-assume-role" {
					t.Errorf("unexpected repo: want %q, got %q", "actions-aws-assume-role", repo)
				}
				if ref != "e3a45c6c16c1464826b36a598ff39e6cc98c4da4" {
					t.Errorf("unexpected ref: want %q, got %q", "e3a45c6c16c1464826b36a598ff39e6cc98c4da4", ref)
				}
				if status.State != github.CommitStateSuccess {
					t.Errorf("unexpected commit status state: want %s, got %s", github.CommitStateSuccess, status.State)
				}
				if status.Context != commitStatusContext {
					t.Errorf("unexpected commit status context: want %q, got %q", commitStatusContext, status.Context)
				}
				return &github.CreateStatusResponse{
					Creator: &github.CreateStatusResponseCreator{
						Login: creatorLogin,
						ID:    creatorID,
						Type:  creatorType,
					},
				}, nil
			},
			ValidateAPIURLFunc: func(url string) error {
				return nil
			},
		},
	}
	err := h.validateGitHubToken(context.Background(), "ghs_dummyGitHubToken", &requestBody{
		Repository: "fuller-inc/actions-aws-assume-role",
		SHA:        "e3a45c6c16c1464826b36a598ff39e6cc98c4da4",
	})
	if err != nil {
		t.Error(err)
	}
}

func TestValidateGitHubToken_PermissionError(t *testing.T) {
	h := &Handler{
		github: &githubClientMock{
			CreateStatusFunc: func(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error) {
				return nil, &github.ErrUnexpectedStatusCode{
					StatusCode: http.StatusBadRequest,
				}
			},
		},
	}
	err := h.validateGitHubToken(context.Background(), "ghs_dummyGitHubToken", &requestBody{
		Repository: "fuller-inc/actions-aws-assume-role",
		SHA:        "e3a45c6c16c1464826b36a598ff39e6cc98c4da4",
	})
	if err == nil {
		t.Error("want error, but not")
	}

	var validate *validationError
	if !errors.As(err, &validate) {
		t.Errorf("want validation error, got %T", err)
	}
}

func TestValidateGitHubToken_InvalidCreator(t *testing.T) {
	h := &Handler{
		github: &githubClientMock{
			CreateStatusFunc: func(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error) {
				return &github.CreateStatusResponse{
					Creator: &github.CreateStatusResponseCreator{
						Login: "shogo82148",
						ID:    1157344,
						Type:  "User",
					},
				}, nil
			},
			ValidateAPIURLFunc: func(url string) error {
				return nil
			},
		},
	}
	err := h.validateGitHubToken(context.Background(), "ghs_dummyGitHubToken", &requestBody{
		Repository: "fuller-inc/actions-aws-assume-role",
		SHA:        "e3a45c6c16c1464826b36a598ff39e6cc98c4da4",
	})
	if err == nil {
		t.Error("want error, but not")
	}

	var validate *validationError
	if !errors.As(err, &validate) {
		t.Errorf("want validation error, got %T", err)
	}
}
