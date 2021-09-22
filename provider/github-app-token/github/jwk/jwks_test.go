package jwk

import (
	"testing"
)

func TestSetAppendixA(t *testing.T) {
	t.Run("RFC 7517 A.1. Example Public Keys", func(t *testing.T) {
		rawKeys := `{` +
			`"keys":` +
			`[` +
			`{"kty":"EC",` +
			`"crv":"P-256",` +
			`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",` +
			`"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",` +
			`"use":"enc",` +
			`"kid":"1"},` +
			`{"kty":"RSA",` +
			`"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx` +
			`4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs` +
			`tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2` +
			`QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI` +
			`SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb` +
			`w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",` +
			`"e":"AQAB",` +
			`"alg":"RS256",` +
			`"kid":"2011-04-29"}` +
			`]` +
			`}`
		set, err := ParseSet([]byte(rawKeys))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := set.Find("2011-04-29")
		if !ok {
			t.Error("key 2011-04-29 is not found")
		}
	})

	t.Run("RFC 7517 A.3. Example Symmetric Keys", func(t *testing.T) {
		rawKeys := `{"keys":` +
			`[` +
			`{"kty":"oct",` +
			`"alg":"A128KW",` +
			`"k":"GawgguFyGrWKav7AX4VKUg"},` +
			`{"kty":"oct",` +
			`"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75` +
			`aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",` +
			`"kid":"HMAC key used in JWS spec Appendix A.1 example"}` +
			`]` +
			`}`
		set, err := ParseSet([]byte(rawKeys))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := set.Find("HMAC key used in JWS spec Appendix A.1 example")
		if !ok {
			t.Error("key \"HMAC key used in JWS spec Appendix A.1 example\" is not found")
		}
	})
}
