package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The thumbprint of Go's test certificate.
// https://github.com/golang/go/blob/a83a5587331392fc9483d183e446586b463ad8aa/src/net/http/internal/testcert/testcert.go#L10-L27
var testThumbprint = []string{"2C11EDD713877DB57418B81C42C2561F0DB95BB9"}

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

	c, err := NewClient(ts.Client(), ts.URL, testThumbprint)
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
