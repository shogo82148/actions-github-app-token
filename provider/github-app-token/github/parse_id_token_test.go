package github

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/shogo82148/goat/oidc"
)

func TestParseIDToken_Integrated(t *testing.T) {
	idToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	idURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if idToken == "" || idURL == "" {
		t.Skip("it is not in GitHub Actions Environment")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Logf("the request started at %s", time.Now())
	token, err := getIdToken(ctx, idToken, idURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the id is issued at %s", time.Now())

	oidcClient, err := oidc.NewClient(&oidc.ClientConfig{
		Doer:   http.DefaultClient,
		Issuer: oidcIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		baseURL:    apiBaseURL,
		httpClient: http.DefaultClient,
		oidcClient: oidcClient,
	}
	id, err := c.ParseIDToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("raw: %#v", id.Raw)

	if got, want := id.Actor, os.Getenv("GITHUB_ACTOR"); got != want {
		t.Errorf("unexpected actor: want %q, got %q", want, got)
	}
	if got, want := id.Repository, os.Getenv("GITHUB_REPOSITORY"); got != want {
		t.Errorf("unexpected repository: want %q, got %q", want, got)
	}
	if got, want := id.EventName, os.Getenv("GITHUB_EVENT_NAME"); got != want {
		t.Errorf("unexpected repository: want %q, got %q", want, got)
	}
}

func getIdToken(ctx context.Context, idToken, idURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, idURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Value string `json:"value"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&result); err != nil {
		return "", err
	}
	return result.Value, nil
}
