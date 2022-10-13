package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/jwt"
	"github.com/shogo82148/goat/sig"
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

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("unexpected Authorization header: %q", auth)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		auth = strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse([]byte(auth), jwt.FindKeyFunc(func(header *jws.Header) (sig.SigningKey, error) {
			if want, got := jwa.RS256, header.Algorithm(); want != got {
				t.Errorf("unexpected algorithm: want %s, got %s", want, got)
			}
			key, err := readPublicKeyForTest()
			if err != nil {
				return nil, err
			}
			return jwa.RS256.New().NewSigningKey(key), nil
		}))
		if err != nil {
			t.Error(err)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims := token.Claims
		iss := claims.Issuer
		if iss != "123456" {
			t.Errorf("unexpected issuer: want %q, got %q", "123456", iss)
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

	c, err := NewClient(nil, 123456, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = ts.URL

	resp, err := c.CreateAppAccessToken(context.Background(), 123456789, &CreateAppAccessTokenRequest{
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
