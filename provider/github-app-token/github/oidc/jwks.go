package oidc

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github/jwk"
)

func (c *Client) GetJWKS(ctx context.Context, url string) (*jwk.Set, error) {
	// TODO: need to cache?
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "application/jwk-set+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// verify the certificate
	if err := c.verifyCertificate(resp); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: unexpected response code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return jwk.ParseSet(data)
}

func (c *Client) verifyCertificate(resp *http.Response) error {
	if resp.TLS == nil {
		return errors.New("oidc: jwks url is not encrypted")
	}
	certs := resp.TLS.PeerCertificates
	if len(certs) == 0 {
		return errors.New("oidc: the server certificate is not found")
	}
	cert := certs[len(certs)-1]
	sum := sha1.Sum(cert.Raw)
	for _, want := range c.thumbprints {
		if subtle.ConstantTimeCompare(sum[:], want) != 0 {
			return nil
		}
	}
	return errors.New("oidc: invalid server certificate")
}
