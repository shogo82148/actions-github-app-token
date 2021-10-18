package oidc

import (
	"strconv"
	"strings"
	"time"
)

type cacheEntry struct {
	URL       string
	ExpiresAt time.Time
	Contents  interface{}
}

type cacheControl struct {
	NoCache bool
	NoStore bool
	MaxAge  time.Duration
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[0:len(prefix)], prefix)
}

func parseCacheControl(header string) *cacheControl {
	var ret cacheControl
	directives := strings.Split(header, ",")
	for _, d := range directives {
		d := strings.TrimSpace(d)
		switch {
		case strings.EqualFold(d, "no-cache"):
			ret.NoCache = true
		case strings.EqualFold(d, "no-store"):
			ret.NoStore = true
		case hasPrefixFold(d, "max-age="):
			v := d[len("max-age="):]
			if maxAge, err := strconv.ParseInt(v, 10, 64); err == nil {
				ret.MaxAge = time.Duration(maxAge) * time.Second
			}
		}
	}

	return &ret
}
