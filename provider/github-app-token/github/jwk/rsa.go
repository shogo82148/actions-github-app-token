package jwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// 6.3.2.  Parameters for RSA Private Keys
type rsaPrivateKey struct {
	commonKey

	// RFC7518 6.3.1.1. "n" (Modulus) Parameter
	N string `json:"n"`

	// RFC7518 6.3.1.2. "e" (Exponent) Parameter
	E string `json:"e"`

	// RFC7518 6.3.2.1. "d" (Private Exponent) Parameter
	D string `json:"d"`

	// RFC7518 6.3.2.2. "p" (First Prime Factor) Parameter
	P string `json:"p"`

	// RFC7518 6.3.2.3. "q" (Second Prime Factor) Parameter
	Q string `json:"q"`

	// RFC7518 6.3.2.4. "dp" (First Factor CRT Exponent) Parameter
	Dp string `json:"dp,omitempty"`

	// RFC7518 6.3.2.5. "dq" (Second Factor CRT Exponent) Parameter
	Dq string `json:"dq,omitempty"`

	// RFC7518 6.3.2.6. "qi" (First CRT Coefficient) Parameter
	Qi string `json:"qi,omitempty"`

	// RFC7518 6.3.2.7. "oth" (Other Primes Info) Parameter
	Oth []struct {
		// RFC7518 6.3.2.7.1. "r" (Prime Factor)
		R string `json:"r"`

		// RFC7518 6.3.2.7.2. "d" (Factor CRT Exponent)
		D string `json:"d"`

		// RFC7518 6.3.2.7.3. "t" (Factor CRT Coefficient)
		T string `json:"t"`
	} `json:"oth,omitempty"`

	privateKey rsa.PrivateKey
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

	// sanity check of the certificate
	if certs := key.X509CertificateChain(); len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("jwk: public key types are mismatch")
		}
		if !key.privateKey.PublicKey.Equal(publicKey) {
			return nil, errors.New("jwk: public keys are mismatch")
		}
	}

	return &key, nil
}

func (key *rsaPrivateKey) PrivateKey() interface{} {
	return &key.privateKey
}

func (key *rsaPrivateKey) PublicKey() interface{} {
	return &key.privateKey.PublicKey
}

func (key *rsaPrivateKey) decode() error {
	// parameters for public key
	dataE, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter e: %w", err)
	}
	var e int
	for _, v := range dataE {
		e = (e << 8) | int(v)
	}
	key.privateKey.E = e

	dataN, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter n: %w", err)
	}
	key.privateKey.N = new(big.Int).SetBytes(dataN)

	// parameters for private key
	dataD, err := base64.RawURLEncoding.DecodeString(key.D)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter d: %w", err)
	}
	key.privateKey.D = new(big.Int).SetBytes(dataD)

	dataP, err := base64.RawURLEncoding.DecodeString(key.P)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter p: %w", err)
	}
	p := new(big.Int).SetBytes(dataP)

	dataQ, err := base64.RawURLEncoding.DecodeString(key.Q)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter q: %w", err)
	}
	q := new(big.Int).SetBytes(dataQ)

	key.privateKey.Primes = []*big.Int{p, q}

	crtValues := make([]rsa.CRTValue, 0, len(key.Oth))
	for i, v := range key.Oth {
		dataR, err := base64.RawURLEncoding.DecodeString(v.R)
		if err != nil {
			return fmt.Errorf("jwk: failed to parse parameter oth[%d].r: %w", i, err)
		}
		r := new(big.Int).SetBytes(dataR)
		key.privateKey.Primes = append(key.privateKey.Primes, r)

		dataD, err := base64.RawURLEncoding.DecodeString(v.D)
		if err != nil {
			return fmt.Errorf("jwk: failed to parse parameter oth[%d].d: %w", i, err)
		}
		d := new(big.Int).SetBytes(dataD)

		dataT, err := base64.RawURLEncoding.DecodeString(v.T)
		if err != nil {
			return fmt.Errorf("jwk: failed to parse parameter oth[%d].d: %w", i, err)
		}
		t := new(big.Int).SetBytes(dataT)

		crtValues = append(crtValues, rsa.CRTValue{
			Exp:   d,
			Coeff: t,
			R:     r,
		})
	}

	// precomputed values
	if key.Dp != "" && key.Dq != "" && key.Qi != "" {
		dataDp, err := base64.RawURLEncoding.DecodeString(key.Q)
		if err != nil {
			return fmt.Errorf("jwk: failed to parse parameter dp: %w", err)
		}
		dp := new(big.Int).SetBytes(dataDp)

		dataDq, err := base64.RawURLEncoding.DecodeString(key.Q)
		if err != nil {
			return fmt.Errorf("jwk: failed to parse parameter dq: %w", err)
		}
		dq := new(big.Int).SetBytes(dataDq)

		dataQi, err := base64.RawURLEncoding.DecodeString(key.Qi)
		if err != nil {
			return fmt.Errorf("jwk: failed to parse parameter qi: %w", err)
		}
		qi := new(big.Int).SetBytes(dataQi)

		key.privateKey.Precomputed = rsa.PrecomputedValues{
			Dp:        dp,
			Dq:        dq,
			Qinv:      qi,
			CRTValues: crtValues,
		}
	}

	return key.privateKey.Validate()
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

	// sanity check of the certificate
	if certs := key.X509CertificateChain(); len(certs) > 0 {
		cert := certs[0]
		publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
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
