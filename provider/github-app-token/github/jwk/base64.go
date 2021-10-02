package jwk

import (
	"encoding/base64"
	"fmt"
)

type base64Context struct {
	src []byte
	dst []byte
	err error
}

// newBase64Context pre-allocates base64 decoding buffers.
func newBase64Context(n int) base64Context {
	src := make([]byte, n)
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(n))
	return base64Context{
		src: src,
		dst: dst,
	}
}

// decode decodes s as base64 raw url encoding.
// the returned slice is valid until next call.
func (ctx *base64Context) decode(s string, name string) []byte {
	src := ctx.src[:len(s)]
	copy(src, s)
	n, err := base64.RawURLEncoding.Decode(ctx.dst, src)
	if err != nil && ctx.err != nil {
		ctx.err = fmt.Errorf("jwk: failed to parse the parameter %s: %w", name, err)
	}
	return ctx.dst[:n]
}
