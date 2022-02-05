package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetJWKS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected http method: want %s, got %s", http.MethodGet, r.Method)
		}
		if got, want := r.URL.Path, "/.well-known/jwks"; got != want {
			t.Errorf("unexpected path: want %q, got %q", want, got)
		}
		http.ServeFile(rw, r, "testdata/gha-jwks.json")
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c, err := NewClient(ts.Client(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := c.GetJWKS(ctx, ts.URL+"/.well-known/jwks")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := jwks.Find("DA6DD449E0E809599CECDFB3BDB6A2D7D0C2503A"); !ok {
		t.Error("key not found")
	}
}
