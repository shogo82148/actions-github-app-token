package github

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github/oidc"
)

const (
	// The value of User-Agent header
	githubUserAgent = "actions-github-token/1.0"

	// The default url of Github API
	defaultAPIBaseURL = "https://api.github.com"

	oidcIssuer = "https://token.actions.githubusercontent.com"
)

var apiBaseURL string

func init() {
	u := os.Getenv("GITHUB_API_URL")
	if u == "" {
		u = defaultAPIBaseURL
	}

	var err error
	apiBaseURL, err = canonicalURL(u)
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
	baseURL    string
	httpClient Doer

	// configure for GitHub App
	appID         uint64
	rsaPrivateKey *rsa.PrivateKey

	// configure for OpenID Connect
	oidcClient *oidc.Client
}

func NewClient(httpClient Doer, appID uint64, privateKey []byte) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	oidcClient, err := oidc.NewClient(httpClient, oidcIssuer)
	if err != nil {
		return nil, err
	}
	c := &Client{
		baseURL:    apiBaseURL,
		httpClient: httpClient,
		appID:      appID,
		oidcClient: oidcClient,
	}

	if privateKey != nil {
		key, err := decodePrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		c.rsaPrivateKey = key
	}

	return c, nil
}

func decodePrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("github: no key found")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("github: unsupported key type %q", block.Type)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// generate JSON Web Token for authentication the app
// https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps#authenticating-as-a-github-app
func (c *Client) generateJWT() (string, error) {
	unix := time.Now().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"nbf": unix - 60,
		// issued at time, 60 seconds in the past to allow for clock drift
		"iat": unix - 60,
		// JWT expiration time (10 minute maximum)
		"exp": unix + (5 * 60),
		// GitHub App's identifier
		"iss": strconv.FormatUint(c.appID, 10),
	})
	return token.SignedString(c.rsaPrivateKey)
}

func (c *Client) ValidateAPIURL(url string) error {
	u, err := canonicalURL(url)
	if err != nil {
		return err
	}
	if u != c.baseURL {
		if c.baseURL == defaultAPIBaseURL {
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

type ErrUnexpectedStatusCode struct {
	StatusCode       int
	Message          string
	DocumentationURL string
}

func (err *ErrUnexpectedStatusCode) Error() string {
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

func newErrUnexpectedStatusCode(resp *http.Response) *ErrUnexpectedStatusCode {
	var data struct {
		Message          string `json:"message"`
		DocumentationURL string `json:"documentation_url"`
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		return &ErrUnexpectedStatusCode{
			StatusCode: resp.StatusCode,
			Message:    err.Error(),
		}
	}
	return &ErrUnexpectedStatusCode{
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
