package memoize

import (
	"context"
	"sync"
	"time"
)

// for testing
var nowFunc = time.Now

// Group memoizes the calls of Func with expiration.
type Group[K comparable, V any] struct {
	mu sync.Mutex      // protects m
	m  map[K]*entry[V] // lazy initialized
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

// Do calls memoized Func.
func (g *Group[K, V]) Do(ctx context.Context, key K, fn func(ctx context.Context) (val V, expiresAt time.Time, err error)) (V, error) {
	now := nowFunc()

	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[K]*entry[V])
	}
	var e *entry[V]
	var ok bool
	if e, ok = g.m[key]; ok {
		if now.Before(e.expiresAt) {
			g.mu.Unlock()
			return e.val, nil
		}
	} else {
		e = &entry[V]{}
		g.m[key] = e
	}

	// the cache is expired or unavailable.
	// call g.Func
	c := e.call
	if c == nil {
		c = new(call[V])
		c.ctx, c.cancel = context.WithCancel(context.Background())
		e.call = c
		go do(g, e, c, key, fn)
	}
	ch := make(chan result[V], 1)
	c.chans = append(c.chans, ch)
	c.runs++
	g.mu.Unlock()

	select {
	case ret := <-ch:
		return ret.val, ret.err
	case <-ctx.Done():
		g.mu.Lock()
		c.runs--
		if c.runs == 0 {
			c.cancel()
			e.call = nil // to avoid adding new channels to c.chans
		}
		g.mu.Unlock()
		var zero V
		return zero, ctx.Err()
	}
}

func do[K comparable, V any](g *Group[K, V], e *entry[V], c *call[V], key K, fn func(ctx context.Context) (V, time.Time, error)) {
	defer c.cancel()

	v, expiresAt, err := fn(c.ctx)
	ret := result[V]{
		val: v,
		err: err,
	}

	// save to the cache
	g.mu.Lock()
	e.call = nil // to avoid adding new channels to c.chans
	chans := c.chans
	if err == nil {
		e.val = v
		e.expiresAt = expiresAt
	}
	g.mu.Unlock()

	// notify the result to the callers
	for _, ch := range chans {
		ch <- ret
	}
}
