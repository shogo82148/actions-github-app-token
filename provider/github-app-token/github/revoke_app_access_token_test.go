package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func TestRevokeAccessToken(t *testing.T) {
	privateKey, err := os.ReadFile("./testdata/id_rsa_for_testing")
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: want GET, got %s", r.Method)
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer ghs_dummyGitHubToken" {
			t.Errorf("unexpected Authorization header got %q, want %q", auth, "Bearer ghs_dummyGitHubToken")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		path := "/installation/token"
		if r.URL.Path != path {
			t.Errorf("unexpected path: want %q, got %q", path, r.URL.Path)
		}

		rw.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c, err := NewClient(nil, 123456, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL, err = url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = c.RevokeAppAccessToken(context.Background(), "ghs_dummyGitHubToken")
	if err != nil {
		t.Fatal(err)
	}
}
