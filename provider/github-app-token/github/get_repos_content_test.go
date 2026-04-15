package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestGetReposContent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: want GET, got %s", r.Method)
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("unexpected Authorization header: %q", auth)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		path := "/repos/shogo82148/actions-github-app-token/contents/.github/actions.yaml"
		if r.URL.Path != path {
			t.Errorf("unexpected path: want %q, got %q", path, r.URL.Path)
		}

		data, err := os.ReadFile("testdata/repos-content.json")
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Content-Length", strconv.Itoa(len(data)))
		rw.WriteHeader(http.StatusOK)
		rw.Write(data)
	}))
	defer ts.Close()

	kmssvc, err := newMockKMSService()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(nil, 123456, kmssvc, "alias/dummy")
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL, err = url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.GetReposContent(context.Background(), "secret", "shogo82148", "actions-github-app-token", "../.github/workflows/../actions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Type != "file" {
		t.Errorf("got %q, want %q", resp.Type, "file")
	}
}
