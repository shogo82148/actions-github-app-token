package memoize

import (
	"context"
	"sync"
	"sync/atomic"
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

func TestDoDupSuppress(t *testing.T) {
	var wg1, wg2 sync.WaitGroup
	c := make(chan string, 1)
	var calls int32
	g := Memo[string, string]{
		Func: func(ctx context.Context, key string) (string, time.Time, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				// First invocation.
				wg1.Done()
			}
			v := <-c
			c <- v // pump; make available for any future calls

			time.Sleep(10 * time.Millisecond) // let more goroutines enter Do

			return v, time.Time{}, nil
		},
	}

	const n = 10
	wg1.Add(1)
	for i := 0; i < n; i++ {
		wg1.Add(1)
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			wg1.Done()
			v, err := g.Call(context.Background(), "key")
			if err != nil {
				t.Errorf("Do error: %v", err)
				return
			}
			if v != "bar" {
				t.Errorf("Do = %T %v; want %q", v, v, "bar")
			}
		}()
	}
	wg1.Wait()
	// At least one goroutine is in fn now and all of them have at
	// least reached the line before the Do.
	c <- "bar"
	wg2.Wait()
	if got := atomic.LoadInt32(&calls); got <= 0 || got >= n {
		t.Errorf("number of calls = %d; want over 0 and less than %d", got, n)
	}
}
