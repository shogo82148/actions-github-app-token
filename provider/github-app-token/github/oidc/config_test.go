package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetConfig(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected http method: want %s, got %s", http.MethodGet, r.Method)
		}
		if got, want := r.URL.Path, "/.well-known/openid-configuration"; got != want {
			t.Errorf("unexpected path: want %q, got %q", want, got)
		}
		http.ServeFile(rw, r, "testdata/gha-openid-configuration.json")
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := NewClient(ts.Client(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	config, err := c.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := config.Issuer, "https://token.actions.githubusercontent.com"; got != want {
		t.Errorf("unexpected issuer: want %q, got %q", want, got)
	}
}
