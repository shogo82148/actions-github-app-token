package jwk

import (
	"errors"
	"fmt"
)

func parseOkpPrivateKey(data []byte, crv string) (Key, error) {
	switch crv {
	case "Ed25519":
		return parseEd25519PrivateKey(data)
	case "":
		return nil, errors.New("jwk: the crv parameter is missing")
	}
	return nil, fmt.Errorf("jwk: unknown crv: %q", crv)
}

func parseOkpPublicKey(data []byte, crv string) (Key, error) {
	switch crv {
	case "Ed25519":
		return parseEd25519PublicKey(data)
	case "":
		return nil, errors.New("jwk: the crv parameter is missing")
	}
	return nil, fmt.Errorf("jwk: unknown crv: %q", crv)
}
