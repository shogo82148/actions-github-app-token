package github

import (
	"crypto/rsa"
	"crypto/x509"
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
)

const (
	githubUserAgent   = "actions-github-token/1.0"
	defaultAPIBaseURL = "https://api.github.com"
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

// Client is a very light weight GitHub API Client.
type Client struct {
	baseURL       string
	httpClient    *http.Client
	appID         uint64
	rsaPrivateKey *rsa.PrivateKey
}

func NewClient(httpClient *http.Client, appID uint64, privateKey []byte) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	c := &Client{
		baseURL:    apiBaseURL,
		httpClient: httpClient,
		appID:      appID,
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
	now := time.Now()
	unix := now.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		// issued at time, 60 seconds in the past to allow for clock drift
		"iat": unix - 60,
		// JWT expiration time (10 minute maximum)
		"exp": unix + (10 * 60),
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

type UnexpectedStatusCodeError struct {
	StatusCode int
}

func (err *UnexpectedStatusCodeError) Error() string {
	return fmt.Sprintf("unexpected status code: %d", err.StatusCode)
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
