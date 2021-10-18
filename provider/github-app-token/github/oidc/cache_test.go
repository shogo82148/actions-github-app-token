package oidc

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseCacheControl(t *testing.T) {
	testcases := []struct {
		in   string
		want *cacheControl
	}{
		{
			in: "no-store,no-cache",
			want: &cacheControl{
				NoStore: true,
				NoCache: true,
			},
		},
		{
			in: " no-store , no-cache ",
			want: &cacheControl{
				NoStore: true,
				NoCache: true,
			},
		},
		{
			in: " NO-STORE , NO-CACHE ",
			want: &cacheControl{
				NoStore: true,
				NoCache: true,
			},
		},
		{
			in: "max-age=604800",
			want: &cacheControl{
				MaxAge: 604800 * time.Second,
			},
		},
		{
			in: "MAX-AGE=604800",
			want: &cacheControl{
				MaxAge: 604800 * time.Second,
			},
		},
	}

	for _, tc := range testcases {
		got := parseCacheControl(tc.in)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("the result of %q is mismatch (-want/+got):\n%s", tc.in, diff)
		}
	}
}
