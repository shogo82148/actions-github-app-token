package memoize

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDo(t *testing.T) {
	ttl := time.Second
	now := time.Unix(1234567890, 0)
	nowFunc = func() time.Time {
		return now
	}

	var calls int
	var g Group[string, int]
	fn := func(ctx context.Context) (int, time.Time, error) {
		calls++
		return calls, now.Add(ttl), nil
	}

	// first call
	got, err := g.Do(context.Background(), "foobar", fn)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("want 1, got %d", got)
	}

	// the cache is still available, fn should not be called.
	now = now.Add(ttl - 1)

	got, err = g.Do(context.Background(), "foobar", fn)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("want 1, got %d", got)
	}

	// the cache is expired, so fn should be called.
	now = now.Add(1)

	got, err = g.Do(context.Background(), "foobar", fn)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Errorf("want 2, got %d", got)
	}
}

func TestDoErr(t *testing.T) {
	var g Group[string, any]
	someErr := errors.New("Some error")
	v, err := g.Do(context.Background(), "key", func(ctx context.Context) (any, time.Time, error) {
		return nil, time.Time{}, someErr
	})
	if err != someErr {
		t.Errorf("Do error = %v; want someErr %v", err, someErr)
	}
	if v != nil {
		t.Errorf("unexpected non-nil value %#v", v)
	}
}

func TestDoDupSuppress(t *testing.T) {
	var g Group[string, string]
	var wg1, wg2 sync.WaitGroup
	c := make(chan string, 1)
	var calls int32
	fn := func(ctx context.Context) (string, time.Time, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			// First invocation.
			wg1.Done()
		}
		v := <-c
		c <- v // pump; make available for any future calls

		time.Sleep(10 * time.Millisecond) // let more goroutines enter Do

		return v, time.Time{}, nil
	}

	const n = 10
	wg1.Add(1)
	for i := 0; i < n; i++ {
		wg1.Add(1)
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			wg1.Done()
			v, err := g.Do(context.Background(), "key", fn)
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

func TestDoCancel(t *testing.T) {
	ch := make(chan struct{}, 1)
	ch1 := make(chan struct{}, 1)
	ch2 := make(chan struct{}, 1)
	fn := func(ctx context.Context) (any, time.Time, error) {
		<-ctx.Done() // block the execution until ctx is canceled.
		if err := ctx.Err(); err != context.Canceled {
			t.Errorf("want context.Canceled, got %v", err)
		}
		ch <- struct{}{}
		return "bar", time.Time{}, nil
	}

	var g Group[string, any]

	// goroutine 1
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() {
		_, err := g.Do(ctx1, "key", fn)
		if err != context.Canceled {
			t.Errorf("want context.Canceled, got %v", err)
		}
		ch1 <- struct{}{}
	}()

	// goroutine 2
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() {
		_, err := g.Do(ctx2, "key", fn)
		if err != context.Canceled {
			t.Errorf("want context.Canceled, got %v", err)
		}
		ch2 <- struct{}{}
	}()

	// wait for goroutine 1 and 2 to be blocked by fn
	for {
		time.Sleep(time.Millisecond)
		g.mu.Lock()
		runs := g.m["key"].call.runs
		g.mu.Unlock()
		if runs == 2 {
			break
		}
	}

	cancel1() // cancel goroutine 1
	select {
	case <-ch1:
		// goroutine 1 should be canceled
	case <-time.After(time.Second):
		t.Fatalf("Do hangs")
	}

	// other goroutines are still blocked
	select {
	case <-ch:
		t.Fatal("should be blocked, but ch is closed")
	case <-ch2:
		t.Fatal("should be blocked, but ch2 is closed")
	case <-time.After(10 * time.Millisecond):
	}

	cancel2() // cancel goroutine 2

	// now all goroutines are canceled
	select {
	case <-ch2:
		// goroutine 1 should be canceled
	case <-time.After(time.Second):
		t.Fatalf("Do hangs")
	}
	select {
	case <-ch:
		// goroutine 1 should be canceled
	case <-time.After(time.Second):
		t.Fatalf("Do hangs")
	}
}
