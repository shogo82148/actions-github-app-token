package memoize

import (
	"context"
	"sync"
	"time"
)

// for testing
var nowFunc = time.Now

// Memo memoizes the calls of Func with expiration.
type Memo[K comparable, V any] struct {
	Func func(ctx context.Context, key K) (V, time.Time, error)

	mu sync.Mutex

	// m is lazy initialized
	m map[K]*entry[V]
}

type entry[V any] struct {
	val       V
	expiresAt time.Time
}

// Call calls memoized Func.
func (memo *Memo[K, V]) Call(ctx context.Context, key K) (V, error) {
	now := nowFunc()

	memo.mu.Lock()
	if memo.m == nil {
		memo.m = make(map[K]*entry[V])
	}
	var e *entry[V]
	var ok bool
	if e, ok = memo.m[key]; ok {
		if now.Before(e.expiresAt) {
			memo.mu.Unlock()
			return e.val, nil
		}
	} else {
		e = &entry[V]{}
	}
	v, expiresAt, err := memo.Func(ctx, key)
	if err != nil {
		memo.mu.Unlock()
		return v, err
	}
	e.val = v
	e.expiresAt = expiresAt
	memo.m[key] = e
	memo.mu.Unlock()

	return v, nil
}
