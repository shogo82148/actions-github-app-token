package github

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	baseURL    string
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		baseURL:    apiBaseURL,
		httpClient: httpClient,
	}
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
