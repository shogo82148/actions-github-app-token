// The package jwk handles JSON Web Key(https://tools.ietf.org/html/rfc7517).
package jwk

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

type Key interface {
	// KeyType returns the "kty" (Key Type) Parameter.
	KeyType() string

	// PublicKeyUse returns the "use" (Public Key Use) Parameter.
	PublicKeyUse() string

	// KeyOperations returns the "key_ops" (Key Operations) Parameter.
	KeyOperations() []string

	// Algorithm returns the "alg" (Algorithm) Parameter.
	Algorithm() string

	// KeyID returns the "kid" (Key ID) Parameter.
	KeyID() string

	// X509URL returns the "x5u" (X.509 URL) Parameter.
	X509URL() string

	// X509CertificateChain returns the "x5c" (X.509 Certificate Chain) Parameter.
	X509CertificateChain() []*x509.Certificate

	// X509CertificateSHA1 returns the "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter.
	X509CertificateSHA1() string

	// X509CertificateSHA256 returns the "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter.
	X509CertificateSHA256() string

	// PrivateKey returns the private key.
	// If the key doesn't contain any private key, it returns nil.
	PrivateKey() interface{}

	// PublicKey returns the public key.
	// If the key doesn't contain any public key, it returns nil.
	PublicKey() interface{}
}

type commonKey struct {
	// RFC7517 4.1. "kty" (Key Type) Parameter
	Kty string `json:"kty"`

	// RFC7517 4.2. "use" (Public Key Use) Parameter
	Use string `json:"use,omitempty"`

	// RFC7517 4.3. "key_ops" (Key Operations) Parameter
	KeyOps []string `json:"key_ops,omitempty"`

	// RFC7517 4.4. "alg" (Algorithm) Parameter
	Alg string `json:"alg,omitempty"`

	// RFC7517 4.5. "kid" (Key ID) Parameter
	Kid string `json:"kid,omitempty"`

	// RFC7517 4.6. "x5u" (X.509 URL) Parameter
	X5u string `json:"x5u,omitempty"`

	// RFC7517 4.7. "x5c" (X.509 Certificate Chain) Parameter
	X5c   [][]byte `json:"x5c,omitempty"`
	certs []*x509.Certificate

	// RFC7517 4.8. "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter
	X5t string `json:"x5t,omitempty"`

	// RFC7517 4.9. "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter
	X5tS256 string `json:"x5t#S256,omitempty"`
}

func (key *commonKey) KeyType() string {
	return key.Kty
}

func (key *commonKey) PublicKeyUse() string {
	return key.Use
}

func (key *commonKey) KeyOperations() []string {
	return key.KeyOps
}

func (key *commonKey) Algorithm() string {
	return key.Alg
}

func (key *commonKey) KeyID() string {
	return key.Kid
}

func (key *commonKey) X509URL() string {
	return key.X5u
}

func (key *commonKey) X509CertificateChain() []*x509.Certificate {
	return key.certs
}

func (key *commonKey) X509CertificateSHA1() string {
	return key.X5t
}

func (key *commonKey) X509CertificateSHA256() string {
	return key.X5tS256
}

func (key *commonKey) PrivateKey() interface{} {
	return nil
}

func (key *commonKey) PublicKey() interface{} {
	return nil
}

func (key *commonKey) decode() error {
	// decode the certificates
	certs := make([]*x509.Certificate, 0, len(key.X5c))
	for _, der := range key.X5c {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	key.certs = certs

	// check thumbprints
	if key.X5t != "" {
		if len(certs) == 0 {
			return errors.New("jwk: the certificate is not found")
		}
		got := sha1.Sum(key.X5c[0])
		want, err := base64.RawURLEncoding.DecodeString(key.X5t)
		if err != nil {
			return fmt.Errorf("jwk: failed to decode the sha-1 thumbprint: %w", err)
		}
		if subtle.ConstantTimeCompare(got[:], want) == 0 {
			return errors.New("jwk: the sha-1 thumbprint of the certificate is missmatch")
		}
	}
	if key.X5tS256 != "" {
		if len(key.X5c) == 0 {
			return errors.New("jwk: the certificate is not found")
		}
		got := sha256.Sum256(key.X5c[0])
		want, err := base64.RawURLEncoding.DecodeString(key.X5tS256)
		if err != nil {
			return fmt.Errorf("jwk: failed to decode the sha-256 thumbprint: %w", err)
		}
		if subtle.ConstantTimeCompare(got[:], want) == 0 {
			return errors.New("jwk: the sha-256 thumbprint of the certificate is missmatch")
		}
	}

	return nil
}

// ParseKey parses a JWK.
func ParseKey(data []byte) (Key, error) {
	var hint struct {
		Kty string          `json:"kty"`
		Crv string          `json:"crv"`
		D   json.RawMessage `json:"d"`
	}

	if err := json.Unmarshal(data, &hint); err != nil {
		return nil, err
	}
	switch hint.Kty {
	case "EC":
		if len(hint.D) > 0 {
			return parseEcdsaPrivateKey(data)
		} else {
			return parseEcdsaPublicKey(data)
		}
	case "RSA":
		if len(hint.D) > 0 {
			return parseRSAPrivateKey(data)
		} else {
			return parseRSAPublicKey(data)
		}
	case "OKP":
		if len(hint.D) > 0 {
			return parseOkpPrivateKey(data, hint.Crv)
		} else {
			return parseOkpPublicKey(data, hint.Crv)
		}
	case "oct":
		return parseSymmetricKey(data)
	default:
		return nil, fmt.Errorf("jwk: unknown key type: %s", hint.Kty)
	}
}
