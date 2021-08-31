package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestCreateStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: want POST, got %s", r.Method)
		}
		path := "/repos/shogo82148/actions-aws-assume-role/statuses/496f02e29cc5760443becd7007049c1a2a502b6f"
		if r.URL.Path != path {
			t.Errorf("unexpected path: want %q, got %q", path, r.URL.Path)
		}

		data, err := os.ReadFile("testdata/status-created.json")
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Content-Length", strconv.Itoa(len(data)))
		rw.WriteHeader(http.StatusCreated)
		rw.Write(data)
	}))
	defer ts.Close()
	c := NewClient(nil)
	c.baseURL = ts.URL

	resp, err := c.CreateStatus(context.Background(), "dummy-auth-token", "shogo82148", "actions-aws-assume-role", "496f02e29cc5760443becd7007049c1a2a502b6f", &CreateStatusRequest{
		State:   CommitStateSuccess,
		Context: "actions-aws-assume-role",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Creator.ID != 1157344 {
		t.Errorf("unexpected creator id: want %d, got %d", 1157344, resp.Creator.ID)
	}
	if resp.Creator.Login != "shogo82148" {
		t.Errorf("unexpected creator login: want %q, got %q", "shogo82148", resp.Creator.Login)
	}
	if resp.Creator.Type != "User" {
		t.Errorf("unexpected creator type: want %q, got %q", "User", resp.Creator.Type)
	}
}
