package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// 6.3.2.  Parameters for RSA Private Keys
type rsaPrivateKey struct {
	commonKey

	// RFC7518 6.3.2.1. "d" (Private Exponent) Parameter
	D string `json:"d"`

	// RFC7518 6.3.2.2. "p" (First Prime Factor) Parameter
	P string `json:"p"`

	// RFC7518 6.3.2.3. "q" (Second Prime Factor) Parameter
	Q string `json:"q"`

	// RFC7518 6.3.2.4. "dp" (First Factor CRT Exponent) Parameter
	DP string `json:"dp"`

	// RFC7518 6.3.2.5. "dq" (Second Factor CRT Exponent) Parameter
	DQ string `json:"dq"`

	// RFC7518 6.3.2.6. "qi" (First CRT Coefficient) Parameter
	QI string `json:"qi"`

	// RFC7518 6.3.2.7. "oth" (Other Primes Info) Parameter
	Oth []struct {
		// RFC7518 6.3.2.7.1. "r" (Prime Factor)
		R string `json:"r"`

		// RFC7518 6.3.2.7.2. "d" (Factor CRT Exponent)
		D string `json:"d"`

		// RFC7518 6.3.2.7.3. "t" (Factor CRT Coefficient)
		T string `json:"t"`
	} `json:"oth,omitempty"`
}

func parseRSAPrivateKey(data []byte) (Key, error) {
	var key rsaPrivateKey
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

func (key *rsaPrivateKey) decode() error {
	return nil
}

// RFC7518 6.3.1. Parameters for RSA Public Keys
type rsaPublicKey struct {
	commonKey

	// RFC7518 6.3.1.1. "n" (Modulus) Parameter
	N string `json:"n"`

	// RFC7518 6.3.1.2. "e" (Exponent) Parameter
	E string `json:"e"`

	publicKey rsa.PublicKey
}

func (key *rsaPublicKey) PublicKey() interface{} {
	return &key.publicKey
}

func parseRSAPublicKey(data []byte) (Key, error) {
	var key rsaPublicKey
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
func (key *rsaPublicKey) decode() error {
	dataE, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter e: %w", err)
	}
	var e int
	for _, v := range dataE {
		e = (e << 8) | int(v)
	}
	key.publicKey.E = e

	dataN, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter n: %w", err)
	}
	key.publicKey.N = new(big.Int).SetBytes(dataN)

	return nil
}
