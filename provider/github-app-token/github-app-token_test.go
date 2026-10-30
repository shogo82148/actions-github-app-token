package githubapptoken

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestServeHTTP_NullBody(t *testing.T) {
	// the github client must not be called for an invalid request body.
	h := &Handler{
		github: &githubClientMock{},
		appID:  1234567890,
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("null"))
	req.Header.Set("Authorization", "Bearer dummy-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: got %d, want %d", rec.Code, http.StatusBadRequest)
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

func TestHandle_NoPermission(t *testing.T) {
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
				content := "repositories: []\n"
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
	_, err := h.handle(context.Background(), "dummy-token", &requestBody{
		Repositories: []string{
			"R_kgDOIeornQ", "R_kgDOIevBqQ",
		},
	})
	if err == nil {
		t.Fatal("want some error, but not")
	}
	if !revoked {
		t.Error("want revoked, but not")
	}

	var forbidden *forbiddenError
	if !errors.As(err, &forbidden) {
		t.Fatalf("want *forbiddenError, but got %T", err)
	}
}

func newConfigResponse(content string) *github.GetReposContentResponse {
	return &github.GetReposContentResponse{
		Type:     "file",
		Encoding: "base64",
		Content:  base64.StdEncoding.EncodeToString([]byte(content)),
	}
}

func TestCheckConfig_Alias(t *testing.T) {
	var ids strings.Builder
	for i := range 500 {
		id := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("010:Repository%d", 100000000+i)))
		fmt.Fprintf(&ids, "  - %s\n", id)
	}

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "alias to a sequence",
			content: "ids: &ids\n  - R_kgDOF8HFZg\nrepositories: *ids\n",
		},
		{
			name:    "anchor on repositories",
			content: "repositories: &r [R_kgDOF8HFZg]\n",
		},
		{
			name:    "alias to a scalar",
			content: "common: &c R_kgDOF8HFZg\nrepositories:\n  - *c\n",
		},
		{
			name:    "merge key",
			content: "defaults: &defaults\n  repositories: [R_kgDOF8HFZg]\n<<: *defaults\n",
		},
		{
			name:    "alias to a long sequence",
			content: "ids: &ids\n" + ids.String() + "  - R_kgDOF8HFZg\nrepositories: *ids\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{}
			info := &github.GetReposInfoResponse{
				ID: 398574950,
			}
			id, err := h.checkConfig(context.Background(), info, newConfigResponse(tt.content), "R_kgDOF8HFZg")
			if err != nil {
				t.Fatal(err)
			}
			if id != 398574950 {
				t.Errorf("unexpected id: got %d, want %d", id, 398574950)
			}
		})
	}
}

// aliasBomb returns a YAML document that expands to width^(levels+1) strings.
func aliasBomb(width, levels int) string {
	var buf strings.Builder
	buf.WriteString("a0: &a0 [" + strings.TrimSuffix(strings.Repeat(`"lol",`, width), ",") + "]\n")
	for i := 1; i <= levels; i++ {
		alias := fmt.Sprintf("*a%d,", i-1)
		fmt.Fprintf(&buf, "a%d: &a%d [%s]\n", i, i, strings.TrimSuffix(strings.Repeat(alias, width), ","))
	}
	fmt.Fprintf(&buf, "repositories: *a%d\n", levels)
	return buf.String()
}

func TestCheckConfig_AliasBomb(t *testing.T) {
	// it expands to 9^7 strings.
	content := aliasBomb(9, 6)

	h := &Handler{}
	info := &github.GetReposInfoResponse{
		ID: 398574950,
	}
	_, err := h.checkConfig(context.Background(), info, newConfigResponse(content), "R_kgDOF8HFZg")
	if !errors.Is(err, errConfigAliasExpansion) {
		t.Errorf("want errConfigAliasExpansion, but got %v", err)
	}
}

func TestCheckAliasExpansion(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "billion laughs",
			content: aliasBomb(10, 8),
		},
		{
			name: "merge key bomb",
			content: "m0: &m0 {k0: v, k1: v, k2: v, k3: v, k4: v, k5: v, k6: v, k7: v, k8: v}\n" +
				"m1: &m1 {<<: [*m0, *m0, *m0, *m0, *m0, *m0, *m0, *m0, *m0]}\n" +
				"m2: &m2 {<<: [*m1, *m1, *m1, *m1, *m1, *m1, *m1, *m1, *m1]}\n" +
				"m3: &m3 {<<: [*m2, *m2, *m2, *m2, *m2, *m2, *m2, *m2, *m2]}\n" +
				"m4: &m4 {<<: [*m3, *m3, *m3, *m3, *m3, *m3, *m3, *m3, *m3]}\n" +
				"m5: &m5 {<<: [*m4, *m4, *m4, *m4, *m4, *m4, *m4, *m4, *m4]}\n" +
				"m6: &m6 {<<: [*m5, *m5, *m5, *m5, *m5, *m5, *m5, *m5, *m5]}\n" +
				"m7: &m7 {<<: [*m6, *m6, *m6, *m6, *m6, *m6, *m6, *m6, *m6]}\n" +
				"repositories: [R_kgDOF8HFZg]\n",
		},
		{
			name:    "circular reference",
			content: "a: &a x\nb: &b [*a, *a]\nc: &a [*b, *b]\nrepositories: [*b, *b, *b]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAliasExpansion([]byte(tt.content))
			if !errors.Is(err, errConfigAliasExpansion) {
				t.Errorf("want errConfigAliasExpansion, but got %v", err)
			}
		})
	}
}
