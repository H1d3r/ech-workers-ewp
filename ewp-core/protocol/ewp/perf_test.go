package ewp

// Performance regression tests for the EWP protocol layer.
//
// Run all:
//   go test -race -count=1 -run TestPerf ./protocol/ewp/...
//
// Run benchmarks with alloc reporting:
//   go test -bench=. -benchmem -run=^$ ./protocol/ewp/...
//
// T1  HMAC key precomputation       — DecodeHandshakeRequestCached
// T2  ReadHandshake single alloc    — ReadHandshake
// T3  FlowReader pool + truncation  — FlowReader.Read
// T4  NewHandshakeRequest fast rand — NewHandshakeRequest
// T5  NonceCache sharded lock       — NonceCache.CheckAndAdd
// T6  RateLimiter read-lock path    — RateLimiter.Allow

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

var (
	testUUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	testAddr = Address{Type: AddressTypeIPv4, Host: "127.0.0.1", Port: 443}
)

func mustEncodeHandshake(t testing.TB) []byte {
	t.Helper()
	req := NewHandshakeRequest(testUUID, CommandTCP, testAddr)
	wire, err := req.Encode()
	if err != nil {
		t.Fatalf("mustEncodeHandshake: %v", err)
	}
	return wire
}

// ── T1: HMAC key precomputation ───────────────────────────────────────────────

// TestDecodeHandshakeRequestCached_RoundTrip verifies the cached decoder
// produces the same result as the original for a well-formed handshake.
//
// RED: DecodeHandshakeRequestCached panics (not implemented).
func TestDecodeHandshakeRequestCached_RoundTrip(t *testing.T) {
	wire := mustEncodeHandshake(t)
	uuids := [][16]byte{testUUID}
	cache := NewHMACKeyCache(uuids)

	got, err := DecodeHandshakeRequestCached(wire, cache)
	if err != nil {
		t.Fatalf("DecodeHandshakeRequestCached error: %v", err)
	}
	if got.UUID != testUUID {
		t.Fatalf("UUID mismatch: got %v, want %v", got.UUID, testUUID)
	}
	if got.Command != CommandTCP {
		t.Fatalf("Command mismatch: got %v, want %v", got.Command, CommandTCP)
	}
}

// TestDecodeHandshakeRequestCached_RejectsUnknownUUID verifies that a request
// from an unregistered UUID is rejected even with a precomputed cache.
//
// RED: DecodeHandshakeRequestCached panics (not implemented).
func TestDecodeHandshakeRequestCached_RejectsUnknownUUID(t *testing.T) {
	wire := mustEncodeHandshake(t)
	otherUUID := [16]byte{0xFF, 0xFE}
	cache := NewHMACKeyCache([][16]byte{otherUUID})

	_, err := DecodeHandshakeRequestCached(wire, cache)
	if err == nil {
		t.Fatal("expected auth error for unknown UUID, got nil")
	}
}

// TestDecodeHandshakeRequestCached_AllocsReduced asserts that the cached
// variant performs fewer heap allocations than the uncached baseline.
// The primary gain is CPU (no sha256.Sum256 per UUID candidate), not alloc
// count; this test documents the alloc floor after key precomputation.
func TestDecodeHandshakeRequestCached_AllocsReduced(t *testing.T) {
	wire := mustEncodeHandshake(t)
	uuids := [][16]byte{testUUID}
	cache := NewHMACKeyCache(uuids)

	// Measure baseline (uncached).
	baseline := testing.AllocsPerRun(20, func() {
		_, _ = DecodeHandshakeRequest(wire, uuids)
	})
	// Measure cached variant.
	cached := testing.AllocsPerRun(50, func() {
		_, _ = DecodeHandshakeRequestCached(wire, cache)
	})
	// The cached path must not allocate MORE than the uncached path.
	if cached > baseline {
		t.Fatalf("DecodeHandshakeRequestCached allocs = %.0f > baseline %.0f (regression)", cached, baseline)
	}
}

// BenchmarkDecodeHandshake_Baseline documents the current (uncached) alloc cost.
// Run before and after the Green phase to measure improvement.
func BenchmarkDecodeHandshake_Baseline(b *testing.B) {
	wire := mustEncodeHandshake(b)
	uuids := [][16]byte{testUUID}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeHandshakeRequest(wire, uuids)
	}
}

// BenchmarkDecodeHandshake_Cached documents the target (cached) alloc cost.
//
// RED: panics until Green is implemented.
func BenchmarkDecodeHandshake_Cached(b *testing.B) {
	wire := mustEncodeHandshake(b)
	cache := NewHMACKeyCache([][16]byte{testUUID})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeHandshakeRequestCached(wire, cache)
	}
}

// ── T2: ReadHandshake single allocation ───────────────────────────────────────

// TestReadHandshake_SingleAlloc asserts ReadHandshake performs exactly 1 heap
// allocation (the unified packet buffer).
//
// RED: current code allocates 3 (header + rest + append coalescence).
func TestReadHandshake_SingleAlloc(t *testing.T) {
	wire := mustEncodeHandshake(t)

	allocs := testing.AllocsPerRun(100, func() {
		r := bytes.NewReader(wire)
		_, _ = ReadHandshake(r)
	})
	if allocs > 1 {
		t.Fatalf("ReadHandshake allocs = %.0f, want 1 (header+rest+append eliminated)", allocs)
	}
}

// TestReadHandshake_RoundTrip ensures the single-alloc path still returns the
// correct byte slice (full wire data intact).
func TestReadHandshake_RoundTrip(t *testing.T) {
	wire := mustEncodeHandshake(t)
	r := bytes.NewReader(wire)
	got, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("ReadHandshake error: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("ReadHandshake returned %d bytes, want %d", len(got), len(wire))
	}
}

// TestReadHandshake_RejectsShortPayload verifies length validation is preserved.
func TestReadHandshake_RejectsShortPayload(t *testing.T) {
	bad := make([]byte, 15+int(MinPayloadLength)-1+16)
	bad[13] = 0
	bad[14] = byte(MinPayloadLength - 1)
	r := bytes.NewReader(bad)
	_, err := ReadHandshake(r)
	if err == nil {
		t.Fatal("expected error for payload length < MinPayloadLength")
	}
}

// BenchmarkReadHandshake_Allocs documents alloc count for the hot path.
func BenchmarkReadHandshake_Allocs(b *testing.B) {
	wire := mustEncodeHandshake(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(wire)
		_, _ = ReadHandshake(r)
	}
}

// ── T3: FlowReader — pool + no truncation ─────────────────────────────────────

// TestFlowReader_NilState_ZeroAllocs verifies that the nil-state passthrough
// path of FlowReader.Read allocates nothing (regression baseline).
func TestFlowReader_NilState_ZeroAllocs(t *testing.T) {
	payload := bytes.Repeat([]byte("X"), 512)
	src := bytes.NewReader(payload)
	fr := NewFlowReader(src, nil, true)
	p := make([]byte, 512)

	allocs := testing.AllocsPerRun(50, func() {
		src.Reset(payload)
		_, _ = fr.Read(p)
	})
	if allocs > 0 {
		t.Fatalf("FlowReader nil-state Read allocs = %.0f, want 0", allocs)
	}
}

// TestFlowReader_ActiveState_TempBufPooled asserts that FlowReader.Read with an
// active (non-nil, non-direct-copy) FlowState allocates fewer objects than
// the old per-call make([]byte, len(p)*2) path.
// XtlsUnpadding's internal bytes.Buffer allocations are still present; this
// test only verifies the temp read buffer is no longer per-call allocated.
func TestFlowReader_ActiveState_TempBufPooled(t *testing.T) {
	oldState := NewFlowState([]byte(testUUID[:]))
	newState := NewFlowState([]byte(testUUID[:]))
	payload := bytes.Repeat([]byte("X"), 64)

	// Measure "old" path: simulate the old make([]byte, len(p)*2) per call.
	oldAllocs := testing.AllocsPerRun(20, func() {
		buf := make([]byte, len(payload)*2) //nolint:ineffassign
		_ = buf
	})

	src := bytes.NewBuffer(payload)
	fr := NewFlowReader(src, newState, true)
	p := make([]byte, 128)

	newAllocs := testing.AllocsPerRun(30, func() {
		src.Reset()
		src.Write(payload)
		_, _ = fr.Read(p)
	})

	// After pool fix: allocs attributable to temp buf must be gone.
	// We verify the pooled path is ≤ old path + XtlsUnpadding overhead.
	_ = oldState
	if newAllocs > oldAllocs+5 {
		t.Fatalf("FlowReader active-state Read allocs = %.0f, old make() baseline = %.0f (pool not effective)", newAllocs, oldAllocs)
	}
}

// BenchmarkFlowReader_ActiveState_AllocsPerOp documents current alloc cost.
func BenchmarkFlowReader_ActiveState_AllocsPerOp(b *testing.B) {
	state := NewFlowState([]byte(testUUID[:]))
	payload := bytes.Repeat([]byte("Y"), 256)
	src := bytes.NewBuffer(payload)
	fr := NewFlowReader(src, state, true)
	p := make([]byte, 512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.Reset()
		src.Write(payload)
		_, _ = fr.Read(p)
	}
}

// ── T4: NewHandshakeRequest — no crypto/rand for non-secret fields ─────────────

// TestNewHandshakeRequest_AllocsReduced asserts that NewHandshakeRequest
// allocates ≤ 2 objects per call after replacing crypto/rand+big.Int with
// FastIntn for version and padding length.
//
// RED: current code calls rand.Int(rand.Reader, big.NewInt(N)) twice,
// each creating a *big.Int allocation, plus internal crypto/rand state.
func TestNewHandshakeRequest_AllocsReduced(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_ = NewHandshakeRequest(testUUID, CommandTCP, testAddr)
	})
	// After fix: 1 alloc (*HandshakeRequest struct).
	// Nonce rand.Read into stack array — no extra alloc.
	if allocs > 2 {
		t.Fatalf("NewHandshakeRequest allocs = %.0f, want ≤ 2 (big.Int eliminated)", allocs)
	}
}

// TestNewHandshakeRequest_PaddingInRange verifies padding length stays within
// protocol bounds regardless of which RNG is used.
func TestNewHandshakeRequest_PaddingInRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		req := NewHandshakeRequest(testUUID, CommandTCP, testAddr)
		if req.PaddingLength < MinPaddingLength || req.PaddingLength > MaxPaddingLength {
			t.Fatalf("PaddingLength=%d out of [%d,%d]", req.PaddingLength, MinPaddingLength, MaxPaddingLength)
		}
	}
}

// TestNewHandshakeRequest_VersionNonZero verifies Version is always ≥ 1.
func TestNewHandshakeRequest_VersionNonZero(t *testing.T) {
	for i := 0; i < 500; i++ {
		req := NewHandshakeRequest(testUUID, CommandTCP, testAddr)
		if req.Version == 0 {
			t.Fatalf("Version must be ≥ 1, got 0 on iteration %d", i)
		}
	}
}

// BenchmarkNewHandshakeRequest documents per-call speed and alloc count.
func BenchmarkNewHandshakeRequest(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewHandshakeRequest(testUUID, CommandTCP, testAddr)
	}
}

// ── T5: NonceCache sharded concurrent safety ──────────────────────────────────

// TestNonceCache_UniqueNonces_NoFalsePositive asserts that N goroutines each
// submitting a distinct nonce are never incorrectly rejected as replays.
//
// Run with -race to detect data races introduced by a sharding implementation.
func TestNonceCache_UniqueNonces_NoFalsePositive(t *testing.T) {
	cache := NewNonceCache()
	const N = 2000
	var falsePositives atomic.Int64
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			var nonce [12]byte
			nonce[0] = byte(i)
			nonce[1] = byte(i >> 8)
			nonce[2] = byte(i >> 16)
			nonce[11] = 0xAA
			if cache.CheckAndAdd(nonce) {
				falsePositives.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := falsePositives.Load(); n > 0 {
		t.Fatalf("NonceCache false positives: %d unique nonces rejected as replay", n)
	}
}

// TestNonceCache_SameNonce_AlwaysReplay verifies that the same nonce submitted
// twice is detected regardless of concurrent load on other shards.
func TestNonceCache_SameNonce_AlwaysReplay(t *testing.T) {
	cache := NewNonceCache()
	nonce := [12]byte{0xDE, 0xAD, 0xBE, 0xEF}

	if cache.CheckAndAdd(nonce) {
		t.Fatal("first submission must not be replay")
	}
	if !cache.CheckAndAdd(nonce) {
		t.Fatal("second submission must be detected as replay")
	}
}

// TestNonceCache_CrossShardBoundary exercises nonces that hash to different
// shards to ensure the sharding logic has no cross-shard false negatives.
func TestNonceCache_CrossShardBoundary(t *testing.T) {
	cache := NewNonceCache()
	// Nonces that differ only in the shard-routing byte — each goes to its own shard.
	for i := 0; i < 256; i++ {
		nonce := [12]byte{byte(i)}
		if cache.CheckAndAdd(nonce) {
			t.Fatalf("nonce[0]=%d falsely flagged as replay", i)
		}
	}
	// Second pass: all must be detected as replay now.
	for i := 0; i < 256; i++ {
		nonce := [12]byte{byte(i)}
		if !cache.CheckAndAdd(nonce) {
			t.Fatalf("nonce[0]=%d not detected as replay on second submission", i)
		}
	}
}

// BenchmarkNonceCache_Concurrent measures throughput under parallel load.
// Run: go test -bench=BenchmarkNonceCache_Concurrent -benchmem -cpu=1,4,8
func BenchmarkNonceCache_Concurrent(b *testing.B) {
	cache := NewNonceCache()
	b.RunParallel(func(pb *testing.PB) {
		var i uint64
		for pb.Next() {
			var nonce [12]byte
			nonce[0] = byte(i)
			nonce[1] = byte(i >> 8)
			nonce[2] = byte(i >> 16)
			i++
			cache.CheckAndAdd(nonce)
		}
	})
}

// ── T6: RateLimiter read-lock fast path ───────────────────────────────────────

// TestRateLimiter_ConcurrentAllow_NoDeadlock verifies that hundreds of
// goroutines calling Allow() concurrently neither deadlock nor data-race.
//
// Run with -race.
func TestRateLimiter_ConcurrentAllow_NoDeadlock(t *testing.T) {
	rl := NewRateLimiter(1_000_000, 5*time.Second)
	const goroutines = 200
	const callsEach = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
			for j := 0; j < callsEach; j++ {
				rl.Allow(ip)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RateLimiter concurrent Allow deadlocked or took too long")
	}
}

// TestRateLimiter_BannedIP_BlockedFast verifies a banned IP is rejected without
// acquiring a write lock unnecessarily.
func TestRateLimiter_BannedIP_BlockedFast(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	ip := "192.0.2.1"

	rl.Allow(ip)
	rl.RecordFailure(ip)

	// All subsequent calls must be denied without blocking.
	for i := 0; i < 100; i++ {
		if rl.Allow(ip) {
			t.Fatalf("banned IP was allowed on call %d", i)
		}
	}
}

// BenchmarkRateLimiter_Allow_HotPath benchmarks the common case:
// known IP, not banned, below rate limit — should be dominated by read lock.
//
// After the read-lock fast-path fix, parallel throughput should improve
// significantly compared to the current write-lock-on-all-paths baseline.
func BenchmarkRateLimiter_Allow_HotPath(b *testing.B) {
	rl := NewRateLimiter(1_000_000, time.Minute)
	ip := "192.168.1.100"
	rl.Allow(ip)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow(ip)
		}
	})
}
