package jwk

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
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
	ctx := key.getContext()

	// parameters for public key
	var e int
	for _, v := range ctx.decode(key.E, "e") {
		e = (e << 8) | int(v)
	}
	key.privateKey.PublicKey.E = e

	key.privateKey.PublicKey.N = new(big.Int).SetBytes(ctx.decode(key.N, "n"))

	// parameters for private key
	key.privateKey.D = new(big.Int).SetBytes(ctx.decode(key.D, "d"))
	p := new(big.Int).SetBytes(ctx.decode(key.P, "p"))
	q := new(big.Int).SetBytes(ctx.decode(key.Q, "q"))

	key.privateKey.Primes = []*big.Int{p, q}

	crtValues := make([]rsa.CRTValue, 0, len(key.Oth))
	for _, v := range key.Oth {
		r := new(big.Int).SetBytes(ctx.decode(v.R, "oth[].r"))
		key.privateKey.Primes = append(key.privateKey.Primes, r)

		d := new(big.Int).SetBytes(ctx.decode(v.D, "oth[].d"))
		t := new(big.Int).SetBytes(ctx.decode(v.T, "oth[].t"))

		crtValues = append(crtValues, rsa.CRTValue{
			Exp:   d,
			Coeff: t,
			R:     r,
		})
	}

	// precomputed values
	if key.Dp != "" && key.Dq != "" && key.Qi != "" {
		dp := new(big.Int).SetBytes(ctx.decode(key.Dp, "dp"))
		dq := new(big.Int).SetBytes(ctx.decode(key.Dp, "dq"))
		qi := new(big.Int).SetBytes(ctx.decode(key.Dp, "qi"))

		key.privateKey.Precomputed = rsa.PrecomputedValues{
			Dp:        dp,
			Dq:        dq,
			Qinv:      qi,
			CRTValues: crtValues,
		}
	}

	if ctx.err != nil {
		return ctx.err
	}
	return key.privateKey.Validate()
}

func (key *rsaPrivateKey) getContext() base64Context {
	var size int
	if len(key.E) > size {
		size = len(key.E)
	}
	if len(key.N) > size {
		size = len(key.N)
	}
	if len(key.D) > size {
		size = len(key.D)
	}
	if len(key.P) > size {
		size = len(key.P)
	}
	if len(key.Q) > size {
		size = len(key.Q)
	}
	for _, v := range key.Oth {
		if len(v.R) > size {
			size = len(v.R)
		}
		if len(v.D) > size {
			size = len(v.D)
		}
		if len(v.D) > size {
			size = len(v.D)
		}
	}
	if len(key.Dp) > size {
		size = len(key.Dp)
	}
	if len(key.Dq) > size {
		size = len(key.Dq)
	}
	if len(key.Qi) > size {
		size = len(key.Qi)
	}
	return newBase64Context(size)
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
	ctx := key.getContext()

	var e int
	for _, v := range ctx.decode(key.E, "e") {
		e = (e << 8) | int(v)
	}
	key.publicKey.E = e

	key.publicKey.N = new(big.Int).SetBytes(ctx.decode(key.N, "n"))

	return ctx.err
}

func (key *rsaPublicKey) getContext() base64Context {
	var size int
	if len(key.E) > size {
		size = len(key.E)
	}
	if len(key.N) > size {
		size = len(key.N)
	}
	return newBase64Context(size)
}
