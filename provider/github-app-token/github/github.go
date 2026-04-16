package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/shogo82148/goat/jwa"
	_ "github.com/shogo82148/goat/jwa/rs" // for RS256
	"github.com/shogo82148/goat/jws"
	"github.com/shogo82148/goat/jwt"
	"github.com/shogo82148/goat/oidc"
	"github.com/shogo82148/goat/sig"
)

const (
	// The value of User-Agent header
	githubUserAgent = "actions-github-token/1.0"

	// The default url of Github API
	defaultAPIBaseURL = "https://api.github.com"

	// issuer of JWT tokens
	oidcIssuer = "https://token.actions.githubusercontent.com"

	// The GitHub API version to use
	// https://docs.github.com/en/rest/about-the-rest-api/api-versions
	githubAPIVersion = "2026-03-10"
)

var apiBaseURL *url.URL

func init() {
	u := os.Getenv("GITHUB_API_URL")
	if u == "" {
		u = defaultAPIBaseURL
	}

	var err error
	apiBaseURL, err = url.Parse(u)
	if err != nil {
		panic(err)
	}
}

// Doer is a interface for doing an http request.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client is a very light weight GitHub API Client.
type Client struct {
	baseURL    *url.URL
	httpClient Doer

	// configure for GitHub App
	appID  uint64
	kmssvc KMSService
	keyID  string

	// configure for OpenID Connect
	oidcClient *oidc.Client
}

// KMSService is a subset of AWS KMS client interface used for signing JWTs.
type KMSService interface {
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

func NewClient(httpClient Doer, appID uint64, kmssvc KMSService, keyID string) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	oidcClient, err := oidc.NewClient(&oidc.ClientConfig{
		Doer:      httpClient,
		Issuer:    oidcIssuer,
		UserAgent: githubUserAgent,
	})
	if err != nil {
		return nil, err
	}

	c := &Client{
		baseURL:    apiBaseURL,
		httpClient: httpClient,
		appID:      appID,
		kmssvc:     kmssvc,
		keyID:      keyID,
		oidcClient: oidcClient,
	}

	return c, nil
}

// generate JSON Web Token for authentication the app
// https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps#authenticating-as-a-github-app
func (c *Client) generateJWT(ctx context.Context) (string, error) {
	if c.kmssvc == nil {
		return "", errors.New("github app KMS service is not configured")
	}
	if c.keyID == "" {
		return "", errors.New("github app KMS key ID is not configured")
	}

	now := time.Now().Truncate(time.Second)
	header := jws.NewHeader()
	header.SetType("JWT")
	header.SetAlgorithm(jwa.RS256)
	claims := &jwt.Claims{
		NotBefore:      now.Add(-60 * time.Second),
		IssuedAt:       now.Add(-60 * time.Second),
		ExpirationTime: now.Add(5 * time.Minute),
		Issuer:         strconv.FormatUint(c.appID, 10),
	}
	token, err := jwt.Sign(header, claims, &key{
		ctx:   ctx,
		svc:   c.kmssvc,
		keyID: c.keyID,
	})
	if err != nil {
		return "", err
	}
	return string(token), nil
}

var _ sig.SigningKey = (*key)(nil)

type key struct {
	ctx   context.Context
	svc   KMSService
	keyID string
}

func (k *key) Sign(data []byte) ([]byte, error) {
	out, err := k.svc.Sign(k.ctx, &kms.SignInput{
		Message:          data,
		KeyId:            &k.keyID,
		MessageType:      kmstypes.MessageTypeRaw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil
}

func (k *key) Verify(data, sig []byte) error {
	return errors.New("not implemented")
}

// ValidateAPIURL validates the API URL of the client. It returns an error if the URL is not valid.
func (c *Client) ValidateAPIURL(url string) error {
	u, err := canonicalURL(url)
	if err != nil {
		return err
	}
	if u != c.baseURL.String() {
		if c.baseURL.String() == defaultAPIBaseURL {
			return errors.New(
				"it looks that you use GitHub Enterprise Server, " +
					"but the credential provider doesn't support it. " +
					"I recommend you to build your own credential provider",
			)
		}
		return errors.New("your api server is not verified by the credential provider")
	}
	return nil
}

type UnexpectedStatusCodeError struct {
	StatusCode       int
	Message          string
	DocumentationURL string
}

func (err *UnexpectedStatusCodeError) Error() string {
	var buf strings.Builder
	buf.WriteString("unexpected status code: ")
	buf.WriteString(strconv.Itoa(err.StatusCode))
	if err.Message != "" {
		buf.WriteString(", message: ")
		buf.WriteString(err.Message)
	}
	if err.DocumentationURL != "" {
		buf.WriteString(", documentation_url: ")
		buf.WriteString(err.DocumentationURL)
	}
	return buf.String()
}

func newErrUnexpectedStatusCode(resp *http.Response) *UnexpectedStatusCodeError {
	var data struct {
		Message          string `json:"message"`
		DocumentationURL string `json:"documentation_url"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		return &UnexpectedStatusCodeError{
			StatusCode: resp.StatusCode,
			Message:    err.Error(),
		}
	}
	return &UnexpectedStatusCodeError{
		StatusCode:       resp.StatusCode,
		Message:          data.Message,
		DocumentationURL: data.DocumentationURL,
	}
}

func canonicalURL(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	port := u.Port()

	// host is case insensitive.
	host = strings.ToLower(host)

	// remove trailing slashes.
	u.Path = strings.TrimRight(u.Path, "/")

	// omit the default port number.
	defaultPort := "80"
	switch u.Scheme {
	case "http":
	case "https":
		defaultPort = "443"
	case "":
		u.Scheme = "http"
	default:
		return "", fmt.Errorf("unknown scheme: %s", u.Scheme)
	}
	if port == defaultPort {
		port = ""
	}

	if port == "" {
		u.Host = host
	} else {
		u.Host = net.JoinHostPort(host, port)
	}

	// we don't use query and fragment, so drop them.
	u.RawFragment = ""
	u.RawQuery = ""

	return u.String(), nil
}
