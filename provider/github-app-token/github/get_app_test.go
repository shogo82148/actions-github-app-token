package github

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestGetApp(t *testing.T) {
	privateKey, err := os.ReadFile("./testdata/id_rsa_for_testing")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		t.Fatal("no key found")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("unsupported key type: %q", block.Type)
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

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
		auth = strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(auth, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return &rsaPrivateKey.PublicKey, nil
		})
		if err != nil {
			t.Error(err)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		claims := token.Claims.(jwt.MapClaims)
		iss := claims["iss"].(string)
		if iss != "123456" {
			t.Errorf("unexpected issuer: want %q, got %q", "123456", iss)
		}

		path := "/app"
		if r.URL.Path != path {
			t.Errorf("unexpected path: want %q, got %q", path, r.URL.Path)
		}

		data, err := os.ReadFile("testdata/app.json")
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Content-Length", strconv.Itoa(len(data)))
		rw.WriteHeader(http.StatusOK)
		rw.Write(data)
	}))
	defer ts.Close()

	c, err := NewClient(nil, 123456, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = ts.URL

	resp, err := c.GetApp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.HTMLURL != "https://github.com/apps/octoapp" {
		t.Errorf("unexpected html url: want %q, got %q", "https://github.com/apps/octoapp", resp.HTMLURL)
	}
}
