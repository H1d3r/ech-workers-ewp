package masque

// Performance and correctness tests for the MASQUE transport layer.
//
// Run:
//   go test -race -count=1 -run TestPerf ./transport/masque/...
//
// T7  time.After timer leak — waitBackoff must release timer on Close()

import (
	"runtime"
	"testing"
	"time"
)

// ── T7: waitBackoff timer leak ────────────────────────────────────────────────

// TestWaitBackoff_ReturnsOnClose verifies that waitBackoff unblocks immediately
// when the transport is closed, even if the backoff window has not expired.
//
// With time.After the internal timer goroutine keeps running until the duration
// elapses; with time.NewTimer + Stop() it is released immediately.
func TestWaitBackoff_ReturnsOnClose(t *testing.T) {
	tr := &Transport{
		stopCh: make(chan struct{}),
	}
	tr.backoffMu.Lock()
	tr.backoffUntil = time.Now().Add(30 * time.Second)
	tr.backoffDelay = backoffMax
	tr.backoffMu.Unlock()

	done := make(chan error, 1)
	go func() { done <- tr.waitBackoff() }()

	time.Sleep(10 * time.Millisecond)
	tr.stopOnce.Do(func() { close(tr.stopCh) })

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("waitBackoff must return non-nil error when transport is closed")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waitBackoff did not unblock within 200ms after Close()")
	}
}

// TestWaitBackoff_TimerNotLeaked verifies that after a Close()-triggered early
// return from waitBackoff, no extra goroutine is left running for the duration
// of the original backoff window.
//
// time.After leaks a runtime timer until it fires; time.NewTimer + Stop()
// cancels it synchronously. We measure the goroutine delta.
func TestWaitBackoff_TimerNotLeaked(t *testing.T) {
	// Stabilise goroutine count before the test.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()

	tr := &Transport{
		stopCh: make(chan struct{}),
	}
	tr.backoffMu.Lock()
	tr.backoffUntil = time.Now().Add(10 * time.Second)
	tr.backoffDelay = backoffMax
	tr.backoffMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.waitBackoff() }()

	time.Sleep(10 * time.Millisecond)
	tr.stopOnce.Do(func() { close(tr.stopCh) })
	<-errCh

	// Allow any deferred cleanup to settle.
	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Accept ±2 for unrelated background goroutines (GC, finaliser, etc.).
	if delta := after - before; delta > 2 {
		t.Fatalf("goroutine leak detected: before=%d after=%d delta=%d (timer not stopped)", before, after, delta)
	}
}

// TestWaitBackoff_NoBackoff_ReturnsImmediately verifies that waitBackoff is a
// no-op when the backoff window has already expired.
func TestWaitBackoff_NoBackoff_ReturnsImmediately(t *testing.T) {
	tr := &Transport{
		stopCh: make(chan struct{}),
	}
	// backoffUntil is zero-value (past), so no sleep should occur.

	done := make(chan error, 1)
	go func() { done <- tr.waitBackoff() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitBackoff with no backoff returned error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("waitBackoff blocked unexpectedly when no backoff was pending")
	}
}

// TestWaitBackoff_BackoffExpires_ReturnsNil verifies that waitBackoff returns
// nil (not an error) when the backoff window expires naturally.
func TestWaitBackoff_BackoffExpires_ReturnsNil(t *testing.T) {
	tr := &Transport{
		stopCh: make(chan struct{}),
	}
	tr.backoffMu.Lock()
	tr.backoffUntil = time.Now().Add(50 * time.Millisecond)
	tr.backoffDelay = 50 * time.Millisecond
	tr.backoffMu.Unlock()

	start := time.Now()
	err := tr.waitBackoff()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected nil after natural backoff expiry, got %v", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("waitBackoff returned too early: elapsed=%v, want ≥40ms", elapsed)
	}
}
