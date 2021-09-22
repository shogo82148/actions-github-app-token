package jwk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// RFC7518 6.4. Parameters for Symmetric Keys
type symmetricKey struct {
	commonKey

	// RFC7518 6.4.1. "k" (Key Value) Parameter
	K string `json:"k"`

	key []byte
}

func parseSymmetricKey(data []byte) (Key, error) {
	var key symmetricKey
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

func (key *symmetricKey) PrivateKey() interface{} {
	return key.key
}

// decode decodes the encoded values into publicKey.
func (key *symmetricKey) decode() error {
	k, err := base64.RawURLEncoding.DecodeString(key.K)
	if err != nil {
		return fmt.Errorf("jwk: failed to parse parameter k: %w", err)
	}
	key.key = k

	return nil
}
