package github

import "testing"

func TestCanonicalURL(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{
			input: "https://api.github.com",
			want:  "https://api.github.com",
		},
		{
			input: "https://API.GITHUB.COM",
			want:  "https://api.github.com",
		},
		{
			input: "https://api.github.com/",
			want:  "https://api.github.com",
		},
		{
			input: "http://example.com/API",
			want:  "http://example.com/API",
		},
		{
			input: "http://example.com/api/",
			want:  "http://example.com/api",
		},
		{
			input: "example.com/api",
			want:  "http://example.com/api",
		},
		{
			input: "http://example.com:80/api",
			want:  "http://example.com/api",
		},
		{
			input: "https://example.com:443/api",
			want:  "https://example.com/api",
		},
		{
			input: "http://example.com:443/api",
			want:  "http://example.com:443/api",
		},
		{
			input: "https://example.com:80/api",
			want:  "https://example.com:80/api",
		},
		{
			input: "https://[::1]:8080/api",
			want:  "https://[::1]:8080/api",
		},
	}
	for i, c := range cases {
		got, err := canonicalURL(c.input)
		if err != nil {
			t.Errorf("%d: canonicalURL(%q) returns error: %v", i, c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("%d: canonicalURL(%q) should be %q, but got %q", i, c.input, c.want, got)
		}
	}
}
