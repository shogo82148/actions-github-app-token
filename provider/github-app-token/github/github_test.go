package github

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/shogo82148/goat/jwa"
	"github.com/shogo82148/goat/jwk"
)

var _ KMSService = (*mockKMSService)(nil)

// mockKMSService is a mock implementation of KMSService for testing.
type mockKMSService struct {
	signFunc func(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *mockKMSService) Sign(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	return m.signFunc(ctx, input, optFns...)
}

func newMockKMSService() (*mockKMSService, error) {
	privateKey, err := os.ReadFile("./testdata/id_rsa_for_testing.pem")
	if err != nil {
		return nil, err
	}
	key, _, err := jwk.DecodePEM(privateKey)
	if err != nil {
		return nil, err
	}
	signer := jwa.RS256.New().NewSigningKey(key)
	return &mockKMSService{
		signFunc: func(ctx context.Context, input *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
			sig, err := signer.Sign(input.Message)
			if err != nil {
				return nil, err
			}
			return &kms.SignOutput{
				Signature: sig,
			}, nil
		},
	}, nil
}

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

func readPublicKeyForTest() (*jwk.Key, error) {
	data, err := os.ReadFile("testdata/id_rsa_pub.json")
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(data)
}
