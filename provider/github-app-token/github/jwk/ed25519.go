package jwk

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// RFC8037 2. Key Type "OKP"
type ed25519PrivateKey struct {
	commonKey

	// the public key encoded
	X string `json:"x"`

	// the private key encoded
	D string `json:"d"`

	// the public key decoded
	publicKey ed25519.PublicKey

	// the private key decoded
	privateKey ed25519.PrivateKey
}

func parseEd25519PrivateKey(data []byte) (Key, error) {
	var key ed25519PrivateKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	if err := key.commonKey.decode(); err != nil {
		return nil, err
	}
	if err := key.decode(); err != nil {
		return nil, err
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain(); len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("jwk: public key types are mismatch")
		}
		if !key.publicKey.Equal(publicKey) {
			return nil, errors.New("jwk: public keys are mismatch")
		}
	}

	return &key, nil
}

func (key *ed25519PrivateKey) PrivateKey() interface{} {
	return key.privateKey
}

func (key *ed25519PrivateKey) PublicKey() interface{} {
	return key.publicKey
}

func (key *ed25519PrivateKey) decode() error {
	ctx := key.getContext()

	privateKey := make([]byte, ed25519.PrivateKeySize)
	data := ctx.decode(key.D, "d")
	if len(data) != ed25519.PrivateKeySize-ed25519.PublicKeySize {
		return fmt.Errorf("jwk: the parameter d has invalid size")
	}
	copy(privateKey, data)

	publicKey := ctx.decode(key.X, "x")
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("jwk: the parameter x has invalid size")
	}
	copy(privateKey[32:], publicKey)

	key.publicKey = ed25519.PublicKey(publicKey)
	key.privateKey = ed25519.PrivateKey(privateKey)

	return ctx.err
}

func (key *ed25519PrivateKey) getContext() base64Context {
	var size int
	if len(key.X) > size {
		size = len(key.X)
	}
	if len(key.D) > size {
		size = len(key.D)
	}
	return newBase64Context(size)
}

// RFC8037 2. Key Type "OKP"
type ed25519PublicKey struct {
	commonKey

	// the public key encoded
	X string `json:"x"`

	// the public key decoded
	publicKey ed25519.PublicKey
}

func (key *ed25519PublicKey) PublicKey() interface{} {
	return key.publicKey
}

func parseEd25519PublicKey(data []byte) (Key, error) {
	var key ed25519PublicKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, err
	}
	if err := key.commonKey.decode(); err != nil {
		return nil, err
	}
	if err := key.decode(); err != nil {
		return nil, err
	}

	// sanity check of the certificate
	if certs := key.X509CertificateChain(); len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("jwk: public key types are mismatch")
		}
		if !key.publicKey.Equal(publicKey) {
			return nil, errors.New("jwk: public keys are mismatch")
		}
	}

	return &key, nil
}

// decode decodes the encoded values into publicKey.
func (key *ed25519PublicKey) decode() error {
	ctx := key.getContext()
	data := ctx.decode(key.X, "x")
	if len(data) != ed25519.PublicKeySize {
		return fmt.Errorf("jwk: the parameter x has invalid size")
	}
	key.publicKey = ed25519.PublicKey(data)
	return ctx.err
}

func (key *ed25519PublicKey) getContext() base64Context {
	return newBase64Context(len(key.X))
}
