package oidc

import (
	"math"
	"math/big"
	"strconv"
	"time"
)

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2.
type NumericDate struct {
	time.Time
}

func (date NumericDate) MarshalJSON() (b []byte, err error) {
	// the maximum time.Time that in Go
	const maxTime = "9223371974719179007.999999999"

	buf := make([]byte, 0, len(maxTime))
	sec := date.Unix()
	buf = strconv.AppendInt(buf, sec, 10)

	if nsec := date.Nanosecond(); nsec != 0 {
		buf = append(buf, '.')
		digits := 100_000_000
		for nsec != 0 {
			d := nsec / digits
			buf = append(buf, byte('0'+d))
			nsec = nsec % digits
			digits /= 10
		}
	}
	return buf, nil
}

var v1_000_000_000 = new(big.Float).SetInt64(1_000_000_000)

func (date *NumericDate) UnmarshalJSON(b []byte) (err error) {
	z := new(big.Float).SetPrec(128)
	if err := z.UnmarshalText(b); err != nil {
		return err
	}
	sec, acc := z.Int64()
	if acc == big.Exact {
		// z is an integer, we don't need to parse nsec.
		date.Time = time.Unix(sec, 0)
		return nil
	}

	z = z.Sub(z, new(big.Float).SetInt64(sec))
	z = z.Mul(z, v1_000_000_000)
	nsec, _ := z.Float64()
	date.Time = time.Unix(sec, int64(math.RoundToEven(nsec)))
	return nil
}
