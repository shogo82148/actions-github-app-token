package jwk

import (
	"crypto/rsa"
	"testing"
)

func TestAppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "RSA" {
			t.Errorf("unexpected key type: want %s, got %s", "RSA", key.KeyType())
		}
		if key.Algorithm() != "RS256" {
			t.Errorf("unexpected algorithm: want %s, got %s", "RS256", key.Algorithm())
		}
		publicKey, ok := key.PublicKey().(*rsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PublicKey, got %T", key.PublicKey())
		}
		if publicKey.E != 65537 {
			t.Errorf("want %d, got %d", 65537, publicKey.E)
		}
	})
}
