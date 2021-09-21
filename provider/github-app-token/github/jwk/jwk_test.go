package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"
)

func TestKeyAppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys (EC)", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "EC" {
			t.Errorf("unexpected key type: want %s, got %s", "RSA", key.KeyType())
		}
		publicKey, ok := key.PublicKey().(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *ecdsa.PublicKey, got %T", key.PublicKey())
		}
		if publicKey.Curve != elliptic.P256() {
			t.Errorf("unexpected curve: want P-256, got %s", publicKey.Curve.Params().Name)
		}
		if got, want := publicKey.X.String(), "21994169848703329112137818087919262246467304847122821377551355163096090930238"; got != want {
			t.Errorf("unexpected x param: want %s, got %s", want, got)
		}
		if got, want := publicKey.Y.String(), "101451294974385619524093058399734017814808930032421185206609461750712400090915"; got != want {
			t.Errorf("unexpected y param: want %s, got %s", want, got)
		}
	})

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
}
