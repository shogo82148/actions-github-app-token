package memoize

import (
	"context"
	"testing"
	"time"
)

func TestCall(t *testing.T) {
	ttl := time.Second
	now := time.Unix(1234567890, 0)
	nowFunc = func() time.Time {
		return now
	}

	var calls int
	memo := &Memo[string, int]{
		Func: func(ctx context.Context, key string) (int, time.Time, error) {
			calls++
			return calls, now.Add(ttl), nil
		},
	}
	got, err := memo.Call(context.Background(), "foobar")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("want 1, got %d", got)
	}

	// the cache is still available, Func should not be called.
	now = now.Add(ttl - 1)

	got, err = memo.Call(context.Background(), "foobar")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("want 1, got %d", got)
	}

	// the cache is expired, so Func should be called.
	now = now.Add(1)

	got, err = memo.Call(context.Background(), "foobar")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("want 2, got %d", got)
	}
}
