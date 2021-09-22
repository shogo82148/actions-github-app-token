package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
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

func (key *ecdsaPrivateKey) PrivateKey() interface{} {
	return &key.privateKey
}

func (key *ecdsaPrivateKey) PublicKey() interface{} {
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

	dataX, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter x: %w", err)
	}
	key.privateKey.X = new(big.Int).SetBytes(dataX)

	dataY, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter y: %w", err)
	}
	key.privateKey.Y = new(big.Int).SetBytes(dataY)

	dataD, err := base64.RawURLEncoding.DecodeString(key.D)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter d: %w", err)
	}
	key.privateKey.D = new(big.Int).SetBytes(dataD)

	return nil
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

func (key *ecdsaPublicKey) PublicKey() interface{} {
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

	dataX, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter x: %w", err)
	}
	key.publicKey.X = new(big.Int).SetBytes(dataX)

	dataY, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter y: %w", err)
	}
	key.publicKey.Y = new(big.Int).SetBytes(dataY)

	return nil
}