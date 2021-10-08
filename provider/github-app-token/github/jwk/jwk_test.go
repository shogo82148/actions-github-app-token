package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestKey_RFC7517AppendixA(t *testing.T) {
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

	t.Run("RFC 7517 A.2. Example Private Keys (EC)", func(t *testing.T) {
		rawKey := `{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"use":"enc",` +
			`"kid":"1"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "EC" {
			t.Errorf("unexpected key type: want %s, got %s", "EC", key.KeyType())
		}
		privateKey, ok := key.PrivateKey().(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("unexpected key type: want *ecdsa.PrivateKey, got %T", key.PrivateKey())
		}
		if privateKey.Curve.Params().Name != "P-256" {
			t.Errorf("unexpected curve: want P-256, got %s", privateKey.Curve.Params().Name)
		}
		publicKey, ok := key.PublicKey().(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *ecdsa.PublicKey, got %T", key.PublicKey())
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			t.Error("public keys are mismatch")
		}
	})

	t.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(t *testing.T) {
		rawKey := `{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",` +
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
		privateKey, ok := key.PrivateKey().(*rsa.PrivateKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PrivateKey, got %T", key.PrivateKey())
		}
		publicKey, ok := key.PublicKey().(*rsa.PublicKey)
		if !ok {
			t.Errorf("unexpected key type: want *rsa.PublicKey, got %T", key.PublicKey())
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			t.Error("public keys are mismatch")
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

func BenchmarkKey_RFC7517AppendixA(b *testing.B) {
	b.Run("RFC 7517 A.1. Example Public Keys (EC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	b.Run("RFC 7517 A.1. Example Public Keys (RSA)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	b.Run("RFC 7517 A.2. Example Private Keys (EC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",` +
			`"use":"enc",` +
			`"kid":"1"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	b.Run("RFC 7517 A.2. Example Private Keys (RSA)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4` +
			`cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst` +
			`n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q` +
			`vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS` +
			`D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw` +
			`0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9` +
			`M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij` +
			`wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d` +
			`_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz` +
			`nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz` +
			`me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",` +
			`"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV` +
			`nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV` +
			`WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",` +
			`"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum` +
			`qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx` +
			`kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",` +
			`"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim` +
			`YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu` +
			`YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",` +
			`"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU` +
			`vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9` +
			`GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",` +
			`"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg` +
			`UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx` +
			`yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	b.Run("RFC 7517 A.3. Example Symmetric Keys (A128KW)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	b.Run("RFC 7517 A.3. Example Symmetric Keys (HMAC)", func(b *testing.B) {
		rawKey := []byte(`{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})
}

func TestKey_RFC7517AppendixB(t *testing.T) {
	// RFC7517 Appendix B. Example Use of "x5c" (X.509 Certificate Chain) Parameter
	rawKey := []byte(`{"kty":"RSA",` +
		`"use":"sig",` +
		`"kid":"1b94c",` +
		`"n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08` +
		`PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q` +
		`u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a` +
		`YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH` +
		`MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv` +
		`VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",` +
		`"e":"AQAB",` +
		`"x5c":` +
		`["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB` +
		`gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD` +
		`VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1` +
		`wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg` +
		`NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV` +
		`QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w` +
		`YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH` +
		`YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66` +
		`s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6` +
		`SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn` +
		`fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq` +
		`PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk` +
		`aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA` +
		`QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL` +
		`+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1` +
		`zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL` +
		`2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo` +
		`4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq` +
		`gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]` +
		`}`)
	key, err := ParseKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyType() != "RSA" {
		t.Errorf("unexpected key type: want %s, got %s", "RSA", key.KeyType())
	}
	if len(key.X509CertificateChain()) != 1 {
		t.Errorf("unexpected certificate chain length: want 1, got %d", len(key.X509CertificateChain()))
	}

	keyPublicKey := key.PublicKey().(*rsa.PublicKey)
	cert := key.X509CertificateChain()[0]
	certPublicKey := cert.PublicKey.(*rsa.PublicKey)
	if !keyPublicKey.Equal(certPublicKey) {
		t.Error("public keys are missmatch")
	}
	issuer := "CN=Brian Campbell,O=Ping Identity Corp.,L=Denver,ST=CO,C=US"
	if cert.Issuer.String() != issuer {
		t.Errorf("unexpected issuer: want %q, got %q", issuer, cert.Issuer.String())
	}
}

func BenchmarkKey_RFC7517AppendixB(b *testing.B) {
	// RFC7517 Appendix B. Example Use of "x5c" (X.509 Certificate Chain) Parameter
	rawKey := []byte(`{"kty":"RSA",` +
		`"use":"sig",` +
		`"kid":"1b94c",` +
		`"n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08` +
		`PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q` +
		`u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a` +
		`YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH` +
		`MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv` +
		`VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",` +
		`"e":"AQAB",` +
		`"x5c":` +
		`["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB` +
		`gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD` +
		`VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1` +
		`wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg` +
		`NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV` +
		`QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w` +
		`YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH` +
		`YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66` +
		`s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6` +
		`SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn` +
		`fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq` +
		`PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk` +
		`aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA` +
		`QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL` +
		`+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1` +
		`zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL` +
		`2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo` +
		`4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq` +
		`gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]` +
		`}`)
	for i := 0; i < b.N; i++ {
		ParseKey(rawKey)
	}
}

func TestKey_RFC8037AppendixA(t *testing.T) {
	t.Run("A.1. Ed25519 Private Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "OKP" {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.KeyType())
		}
		privateKey, ok := key.PrivateKey().(ed25519.PrivateKey)
		if !ok {
			t.Errorf("unexpected private key type: want ed25519.PrivateKey, got %T", key.PrivateKey())
		}
		privateKeyExpected := ed25519.PrivateKey{
			0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
			0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !privateKey.Equal(privateKeyExpected) {
			t.Errorf("unexpected private key: want %x, got %x", privateKeyExpected, privateKey)
		}

		publicKey, ok := key.PublicKey().(ed25519.PublicKey)
		if !ok {
			t.Errorf("unexpected public key type: want ed25519.PublicKey, got %T", key.PublicKey())
		}
		publicKeyExpected := ed25519.PublicKey{
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !publicKey.Equal(publicKeyExpected) {
			t.Errorf("unexpected public key: want %x, got %x", publicKeyExpected, publicKey)
		}
	})

	t.Run("A.2. Ed25519 Public Key", func(t *testing.T) {
		rawKey := `{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
		key, err := ParseKey([]byte(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		if key.KeyType() != "OKP" {
			t.Errorf("unexpected key type: want %s, got %s", "OKP", key.KeyType())
		}

		publicKey, ok := key.PublicKey().(ed25519.PublicKey)
		if !ok {
			t.Errorf("unexpected public key type: want ed25519.PublicKey, got %T", key.PublicKey())
		}
		publicKeyExpected := ed25519.PublicKey{
			0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
			0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
		}
		if !publicKey.Equal(publicKeyExpected) {
			t.Errorf("unexpected public key: want %x, got %x", publicKeyExpected, publicKey)
		}
	})
}

func BenchmarkKey_RFC8037AppendixA(b *testing.B) {
	b.Run("A.1. Ed25519 Private Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})

	b.Run("A.2. Ed25519 Public Key", func(b *testing.B) {
		rawKey := []byte(`{"kty":"OKP","crv":"Ed25519",` +
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`)
		for i := 0; i < b.N; i++ {
			ParseKey(rawKey)
		}
	})
}
