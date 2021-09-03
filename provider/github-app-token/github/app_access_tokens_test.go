package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestCreateAppAccessToken(t *testing.T) {
	privateKey, err := os.ReadFile("./testdata/id_rsa_for_testing")
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: want POST, got %s", r.Method)
		}
		path := "/app/installations/123456789/access_tokens"
		if r.URL.Path != path {
			t.Errorf("unexpected path: want %q, got %q", path, r.URL.Path)
		}

		data, err := os.ReadFile("testdata/access-tokens.json")
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Content-Length", strconv.Itoa(len(data)))
		rw.WriteHeader(http.StatusCreated)
		rw.Write(data)
	}))
	defer ts.Close()

	c, err := NewClient(nil, "123456", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = ts.URL

	resp, err := c.CreateAppAccessToken(context.Background(), "123456789", &CreateAppAccessTokenRequest{
		Repositories: []string{"repositories"},
		Permissions: &CreateAppAccessTokenRequestPermissions{
			Contents: "read",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Token != "ghs_dummyGitHubToken" {
		t.Errorf("unexpected access token: want %q, got %q", "ghs_dummyGitHubToken", resp.Token)
	}
}
