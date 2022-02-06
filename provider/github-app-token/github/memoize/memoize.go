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
	call      *call[V]
}

type call[V any] struct {
	ctx    context.Context
	cancel context.CancelFunc
	runs   int
	chans  []chan<- result[V]
}

type result[V any] struct {
	val V
	err error
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
		memo.m[key] = e
	}

	// the cache is expired or unavailable.
	// call memo.Func
	c := e.call
	if c == nil {
		c = new(call[V])
		c.ctx, c.cancel = context.WithCancel(context.Background())
		e.call = c
		go doCall(memo, e, c, key)
	}
	ch := make(chan result[V], 1)
	c.chans = append(c.chans, ch)
	c.runs++
	memo.mu.Unlock()

	select {
	case ret := <-ch:
		return ret.val, ret.err
	case <-ctx.Done():
		memo.mu.Lock()
		c.runs--
		if c.runs == 0 {
			c.cancel()
		}
		memo.mu.Unlock()
		var zero V
		return zero, ctx.Err()
	}
}

func doCall[K comparable, V any](memo *Memo[K, V], e *entry[V], c *call[V], key K) {
	// call memo.Func
	v, expiresAt, err := memo.Func(c.ctx, key)
	ret := result[V]{
		val: v,
		err: err,
	}

	// save the cache
	memo.mu.Lock()
	e.call = nil
	chans := c.chans
	if err == nil {
		e.val = v
		e.expiresAt = expiresAt
	}
	memo.mu.Unlock()

	// notify the result to the callers
	for _, ch := range chans {
		ch <- ret
	}
}
