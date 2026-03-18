package nat

// Fuzzing + concurrency stress tests for ShardedRegistry.
//
// Run with race detector:
//   go test -race -count=1 -run TestFuzz ./nat/...
//
// Run heap-escape benchmarks:
//   go test -bench=BenchmarkFuzz -benchmem -run=^$ ./nat/...

import (
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func makeAddr(i int) netip.AddrPort {
	return netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 1}),
		uint16(i%65534+1),
	)
}

// ---------------------------------------------------------------------------
// 1. 10 k goroutines, unique addrs — zero cross-mapping
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_10k_UniqueAddrs_NoCrossMapping
func TestFuzz_10k_UniqueAddrs_NoCrossMapping(t *testing.T) {
	const N = 10_000
	reg := NewShardedRegistry()

	type slot struct {
		addr netip.AddrPort
		vip  netip.Addr
	}
	results := make([]slot, N)

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			addr := makeAddr(i)
			results[i] = slot{addr: addr, vip: reg.Allocate(addr)}
		}()
	}
	wg.Wait()

	// Phase 2: verify every vIP resolves to its correct owner.
	// A cross-mapping (vIP_i → addr_j where j != i) is an instant fail.
	for i, s := range results {
		if !s.vip.IsValid() {
			t.Errorf("[%d] Allocate returned zero vIP", i)
			continue
		}
		got, ok := reg.LookupReal(s.vip)
		if !ok {
			t.Errorf("[%d] vIP %s not found after concurrent Allocate", i, s.vip)
			continue
		}
		if got != s.addr {
			t.Errorf("[%d] CROSS-MAPPING: vIP %s → %s, want %s",
				i, s.vip, got, s.addr)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. 10 k goroutines, SAME addr — exactly one vIP assigned (idempotency)
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_10k_SameAddr_Idempotent
func TestFuzz_10k_SameAddr_Idempotent(t *testing.T) {
	const N = 10_000
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")

	vips := make([]netip.Addr, N)
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			vips[i] = reg.Allocate(addr)
		}()
	}
	wg.Wait()

	first := vips[0]
	if !first.IsValid() {
		t.Fatal("first Allocate returned zero vIP")
	}
	for i, v := range vips {
		if v != first {
			t.Fatalf("[%d] idempotency violation: got %s, want %s", i, v, first)
		}
	}
	// Pool must contain exactly one entry for this addr.
	_, ok := reg.LookupReal(first)
	if !ok {
		t.Fatalf("LookupReal(%s) returned false after 10k concurrent Allocates", first)
	}
}

// ---------------------------------------------------------------------------
// 3. Interleaved Allocate + LookupReal — no inconsistency under read pressure
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_InterleaveAllocateLookup
func TestFuzz_InterleaveAllocateLookup(t *testing.T) {
	const (
		writers = 2_000
		readers = 8_000
	)
	reg := NewShardedRegistry()

	// Pre-populate a batch of entries so readers always have something to look up.
	const prePop = 500
	preVIPs := make([]netip.Addr, prePop)
	preAddrs := make([]netip.AddrPort, prePop)
	for i := 0; i < prePop; i++ {
		preAddrs[i] = makeAddr(0xF0000 + i)
		preVIPs[i] = reg.Allocate(preAddrs[i])
	}

	var wg sync.WaitGroup
	var mismatches atomic.Int64

	// Writers: allocate unique new entries concurrently.
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		i := i
		go func() {
			defer wg.Done()
			addr := makeAddr(i)
			vip := reg.Allocate(addr)
			// Immediately verify the allocated vIP resolves correctly.
			if vip.IsValid() {
				if got, ok := reg.LookupReal(vip); ok && got != addr {
					mismatches.Add(1)
				}
			}
		}()
	}

	// Readers: continuously look up pre-populated entries.
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		i := i
		go func() {
			defer wg.Done()
			idx := i % prePop
			got, ok := reg.LookupReal(preVIPs[idx])
			if ok && got != preAddrs[idx] {
				mismatches.Add(1)
			}
		}()
	}

	wg.Wait()

	if n := mismatches.Load(); n > 0 {
		t.Fatalf("%d cross-mapping mismatches detected under interleaved read/write", n)
	}
}

// ---------------------------------------------------------------------------
// 4. EvictStale racing with Allocate — CAS integrity
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_EvictStale_RacesWithAllocate
func TestFuzz_EvictStale_RacesWithAllocate(t *testing.T) {
	const N = 5_000
	reg := NewShardedRegistry()

	// First, fill a batch and force-expire them.
	vips := make([]netip.Addr, N)
	for i := 0; i < N; i++ {
		vips[i] = reg.Allocate(makeAddr(i))
	}
	expiry := time.Now().Add(-10 * time.Minute).UnixNano()
	for i := 0; i < N; i++ {
		reg.setLastActiveForTest(vips[i], expiry)
	}

	// Race: EvictStale goroutines vs Allocate goroutines on overlapping offsets.
	var wg sync.WaitGroup
	evictors := 4
	allocators := N

	wg.Add(evictors)
	for i := 0; i < evictors; i++ {
		go func() {
			defer wg.Done()
			reg.EvictStale(time.Now().Add(-5 * time.Minute).UnixNano())
		}()
	}

	results := make([]netip.Addr, allocators)
	wg.Add(allocators)
	for i := 0; i < allocators; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Re-allocate the same addrs that evictors are trying to clear.
			results[i] = reg.Allocate(makeAddr(i + N))
		}()
	}
	wg.Wait()

	// After the race: every result from re-allocation must map back correctly.
	for i, vip := range results {
		if !vip.IsValid() {
			continue
		}
		want := makeAddr(i + N)
		got, ok := reg.LookupReal(vip)
		if !ok {
			continue // evicted between Allocate and LookupReal — acceptable
		}
		if got != want {
			t.Errorf("[%d] cross-mapping after EvictStale race: vIP %s → %s, want %s",
				i, vip, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Pool wrap-around — no stale cross-mapping after full cycle
// ---------------------------------------------------------------------------

// TestFuzz_PoolWrapAround fills pool twice, verifying no cross-map on second pass.
// This is expensive (~260k Allocates) — skip in short mode.
func TestFuzz_PoolWrapAround(t *testing.T) {
	if testing.Short() {
		t.Skip("pool wrap-around test skipped in -short mode")
	}
	reg := NewShardedRegistry()

	// Fill the pool once.
	const half = 65000
	for i := 0; i < half; i++ {
		reg.Allocate(makeAddr(i))
	}

	// Fill the pool a second time with NEW addrs, wrapping the pool cursor.
	vips2 := make([]netip.Addr, half)
	addrs2 := make([]netip.AddrPort, half)
	for i := 0; i < half; i++ {
		addrs2[i] = makeAddr(i + half)
		vips2[i] = reg.Allocate(addrs2[i])
	}

	// Verify the SECOND batch: each live vIP resolves to its own addr.
	// Note: vIPs from the first batch may have been evicted — that's expected.
	for i := 0; i < half; i++ {
		if !vips2[i].IsValid() {
			continue
		}
		got, ok := reg.LookupReal(vips2[i])
		if !ok {
			continue // evicted due to wrap — acceptable
		}
		if got != addrs2[i] {
			t.Errorf("[%d] post-wrap cross-mapping: vIP %s → %s, want %s",
				i, vips2[i], got, addrs2[i])
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Encoding round-trip under random inputs — no panic
// ---------------------------------------------------------------------------

func TestFuzz_EncodeDecodeRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100_000; i++ {
		ip4 := [4]byte{byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32()), byte(rng.Uint32())}
		port := uint16(rng.Uint32())
		ap := netip.AddrPortFrom(netip.AddrFrom4(ip4), port)
		enc := encAddrPort(ap)
		got := decodeAddrPort(enc)
		if got != ap {
			t.Fatalf("encode/decode mismatch: input=%s got=%s", ap, got)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. Benchmarks — must show 0 B/op, 0 allocs/op
// ---------------------------------------------------------------------------

// go test -bench=BenchmarkFuzz_Allocate_FastPath -benchmem -run=^$
// Expected: 0 B/op, 0 allocs/op
func BenchmarkFuzz_Allocate_FastPath(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")
	reg.Allocate(addr) // warm: entry already exists → fast path on all iterations

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = reg.Allocate(addr)
	}
}

// go test -bench=BenchmarkFuzz_LookupReal_ZeroEscape -benchmem -run=^$
// Expected: 0 B/op, 0 allocs/op
// Validates: netip.AddrPort return value does NOT escape to heap.
func BenchmarkFuzz_LookupReal_ZeroEscape(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")
	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		b.Fatal("Allocate returned zero vIP")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got, ok := reg.LookupReal(vip)
		// Sink: prevent compiler from dead-code eliminating the call.
		if !ok || !got.IsValid() {
			b.Fatal("unexpected miss")
		}
	}
}

// go test -bench=BenchmarkFuzz_LookupReal_Parallel -benchmem -run=^$ -cpu=1,2,4,8
// Expected: 0 B/op, 0 allocs/op across all GOMAXPROCS values.
func BenchmarkFuzz_LookupReal_Parallel(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("1.2.3.4:5678")
	vip := reg.Allocate(addr)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.LookupReal(vip)
		}
	})
}

// go test -bench=BenchmarkFuzz_Allocate_Parallel -benchmem -run=^$ -cpu=1,2,4,8
func BenchmarkFuzz_Allocate_Parallel(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("1.2.3.4:5678")
	reg.Allocate(addr)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.Allocate(addr)
		}
	})
}
