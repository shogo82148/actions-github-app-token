package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// RFC7518 6.2.2. Parameters for Elliptic Curve Private Keys
type ecdsaPrivateKey struct {
	commonKey

	// RFC7518 6.2.1.1. "crv" (Curve) Parameter
	Crv string `json:"crv"`

	// RFC7518 6.2.1.2. "x" (X Coordinate) Parameter
	X string `json:"x"`

	// RFC7518 6.2.1.3. "y" (Y Coordinate) Parameter
	Y string `json:"y"`

	// RFC7518 6.2.2.1. "d" (ECC Private Key) Parameter
	D string `json:"d"`

	privateKey ecdsa.PrivateKey
}

func (key *ecdsaPrivateKey) PrivateKey() any {
	return &key.privateKey
}

func (key *ecdsaPrivateKey) PublicKey() any {
	return &key.privateKey.PublicKey
}

func parseEcdsaPrivateKey(data []byte) (Key, error) {
	var key ecdsaPrivateKey
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
		publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("jwk: public key types are mismatch")
		}
		if !key.privateKey.PublicKey.Equal(publicKey) {
			return nil, errors.New("jwk: public keys are mismatch")
		}
	}

	return &key, nil
}

// decode decodes the encoded values into publicKey.
func (key *ecdsaPrivateKey) decode() error {
	switch key.Crv {
	case "P-224":
		key.privateKey.Curve = elliptic.P224()
	case "P-256":
		key.privateKey.Curve = elliptic.P256()
	case "P-384":
		key.privateKey.Curve = elliptic.P384()
	case "P-521":
		key.privateKey.Curve = elliptic.P521()
	default:
		return fmt.Errorf("jwk: unknown elliptic curve: %q", key.Crv)
	}

	ctx := key.getContext()
	key.privateKey.X = new(big.Int).SetBytes(ctx.decode(key.X, "x"))
	key.privateKey.Y = new(big.Int).SetBytes(ctx.decode(key.Y, "y"))
	key.privateKey.D = new(big.Int).SetBytes(ctx.decode(key.D, "d"))

	return ctx.err
}

func (key *ecdsaPrivateKey) getContext() base64Context {
	var size int
	if len(key.X) > size {
		size = len(key.X)
	}
	if len(key.Y) > size {
		size = len(key.Y)
	}
	if len(key.D) > size {
		size = len(key.D)
	}
	return newBase64Context(size)
}

// RFC7518 6.2.1. Parameters for Elliptic Curve Public Keys
type ecdsaPublicKey struct {
	commonKey

	// RFC7518 6.2.1.1. "crv" (Curve) Parameter
	Crv string `json:"crv"`

	// RFC7518 6.2.1.2. "x" (X Coordinate) Parameter
	X string `json:"x"`

	// RFC7518 6.2.1.3. "y" (Y Coordinate) Parameter
	Y string `json:"y"`

	publicKey ecdsa.PublicKey
}

func (key *ecdsaPublicKey) PublicKey() any {
	return &key.publicKey
}

func parseEcdsaPublicKey(data []byte) (Key, error) {
	var key ecdsaPublicKey
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
		publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
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
func (key *ecdsaPublicKey) decode() error {
	switch key.Crv {
	case "P-224":
		key.publicKey.Curve = elliptic.P224()
	case "P-256":
		key.publicKey.Curve = elliptic.P256()
	case "P-384":
		key.publicKey.Curve = elliptic.P384()
	case "P-521":
		key.publicKey.Curve = elliptic.P521()
	default:
		return fmt.Errorf("jwk: unknown elliptic curve: %q", key.Crv)
	}

	ctx := key.getContext()
	key.publicKey.X = new(big.Int).SetBytes(ctx.decode(key.X, "x"))
	key.publicKey.Y = new(big.Int).SetBytes(ctx.decode(key.Y, "y"))

	return ctx.err
}

func (key *ecdsaPublicKey) getContext() base64Context {
	var size int
	if len(key.X) > size {
		size = len(key.X)
	}
	if len(key.Y) > size {
		size = len(key.Y)
	}
	return newBase64Context(size)
}
