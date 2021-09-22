package jwk

import (
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestKeyAppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`
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

	t.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(t *testing.T) {
		rawKey := `{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "oct" {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.KeyType())
		}
		if key.Algorithm() != "A128KW" {
			t.Errorf("unexpected algorithm: want %s, got %s", "A128KW", key.Algorithm())
		}
		got, ok := key.PrivateKey().([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey())
		}
		want := []byte{
			0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5,
			0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52,
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(t *testing.T) {
		rawKey := `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "oct" {
			t.Errorf("unexpected key type: want %s, got %s", "oct", key.KeyType())
		}
		got, ok := key.PrivateKey().([]byte)
		if !ok {
			t.Errorf("unexpected key type: want []byte, got %T", key.PublicKey())
		}
		want := []byte{
			0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
			0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
			0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
			0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
			0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
			0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
			0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
			0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("unexpected key value: want %x, got %x", want, got)
		}
	})
}
