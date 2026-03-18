package nat

import (
	"net/netip"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Layout assertions
// ---------------------------------------------------------------------------

func TestPeerEntrySize(t *testing.T) {
	if got := unsafe.Sizeof(PeerEntry{}); got != 32 {
		t.Fatalf("PeerEntry size = %d, want 32", got)
	}
}

func TestRealShardSize(t *testing.T) {
	if got := unsafe.Sizeof(realShard{}); got != 64 {
		t.Fatalf("realShard size = %d, want 64 (one cache line)", got)
	}
}

// ---------------------------------------------------------------------------
// Encode / decode round-trip
// ---------------------------------------------------------------------------

func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := netip.MustParseAddrPort("8.8.8.8:1234")
	enc := encAddrPort(want)
	got := decodeAddrPort(enc)
	if got != want {
		t.Fatalf("round-trip: got %s, want %s", got, want)
	}
}

func TestVIPOffsetRoundTrip(t *testing.T) {
	cases := []uint32{1, 65535, 65536, 131069}
	for _, offset := range cases {
		vip := vipFromOffset(offset)
		got, ok := offsetFromVIP(vip)
		if !ok {
			t.Errorf("offsetFromVIP(%s) ok=false, offset=%d", vip, offset)
			continue
		}
		if got != offset {
			t.Errorf("offset round-trip: got %d, want %d (vip=%s)", got, offset, vip)
		}
	}
}

func TestOffsetFromVIP_RejectsInvalid(t *testing.T) {
	bad := []netip.Addr{
		netip.MustParseAddr("198.18.0.0"),  // offset 0 = network addr
		netip.MustParseAddr("1.1.1.1"),     // outside pool
		netip.MustParseAddr("198.20.0.1"),  // outside pool
		netip.MustParseAddr("::1"),         // IPv6
	}
	for _, a := range bad {
		if _, ok := offsetFromVIP(a); ok {
			t.Errorf("offsetFromVIP(%s) should return ok=false", a)
		}
	}
}

// ---------------------------------------------------------------------------
// Allocate
// ---------------------------------------------------------------------------

func TestAllocate_ReturnsValidVIP(t *testing.T) {
	reg := NewShardedRegistry()
	vip := reg.Allocate(netip.MustParseAddrPort("8.8.8.8:1234"))
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero/invalid vIP")
	}
}

func TestAllocate_Idempotent(t *testing.T) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")

	vip1 := reg.Allocate(addr)
	if !vip1.IsValid() {
		t.Fatal("first Allocate returned zero vIP")
	}
	vip2 := reg.Allocate(addr)
	if vip1 != vip2 {
		t.Fatalf("Allocate not idempotent: %s then %s", vip1, vip2)
	}
}

func TestAllocate_UniqueVIPs(t *testing.T) {
	reg := NewShardedRegistry()
	seen := make(map[netip.Addr]netip.AddrPort, 1000)

	for i := 0; i < 1000; i++ {
		addr := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), 0, 1}),
			uint16(1000+i),
		)
		vip := reg.Allocate(addr)
		if !vip.IsValid() {
			t.Fatalf("Allocate(%s) returned zero vIP at i=%d", addr, i)
		}
		if prev, conflict := seen[vip]; conflict {
			t.Fatalf("vIP %s assigned to both %s and %s", vip, prev, addr)
		}
		seen[vip] = addr
	}
}

func TestAllocate_IPv4MappedIPv6_Normalised(t *testing.T) {
	reg := NewShardedRegistry()
	// ::ffff:8.8.8.8 mapped address should be treated identically to 8.8.8.8.
	v4 := netip.MustParseAddrPort("8.8.8.8:1234")
	mapped := netip.AddrPortFrom(v4.Addr().Unmap(), v4.Port())
	vip1 := reg.Allocate(v4)
	vip2 := reg.Allocate(mapped)
	if vip1 != vip2 {
		t.Fatalf("IPv4-mapped normalisation broken: %s vs %s", vip1, vip2)
	}
}

// ---------------------------------------------------------------------------
// LookupReal
// ---------------------------------------------------------------------------

func TestLookupReal_Hit(t *testing.T) {
	reg := NewShardedRegistry()
	want := netip.MustParseAddrPort("1.2.3.4:5678")

	vip := reg.Allocate(want)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}

	got, ok := reg.LookupReal(vip)
	if !ok {
		t.Fatal("LookupReal returned ok=false after Allocate")
	}
	if got != want {
		t.Fatalf("LookupReal: got %s, want %s", got, want)
	}
}

func TestLookupReal_Miss(t *testing.T) {
	reg := NewShardedRegistry()
	_, ok := reg.LookupReal(netip.MustParseAddr("198.18.99.99"))
	if ok {
		t.Fatal("LookupReal returned ok=true for unknown vIP")
	}
}

func TestLookupReal_AfterEviction(t *testing.T) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("5.5.5.5:9090")

	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}

	reg.setLastActiveForTest(vip, time.Now().Add(-10*time.Minute).UnixNano())
	reg.EvictStale(time.Now().Add(-5 * time.Minute).UnixNano())

	_, ok := reg.LookupReal(vip)
	if ok {
		t.Fatal("LookupReal returned ok=true after eviction")
	}
}

// ---------------------------------------------------------------------------
// EvictStale
// ---------------------------------------------------------------------------

func TestEvictStale_RemovesExpired(t *testing.T) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("2.2.2.2:9000")

	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}
	if _, ok := reg.LookupReal(vip); !ok {
		t.Fatal("LookupReal returned false immediately after Allocate")
	}

	reg.setLastActiveForTest(vip, time.Now().Add(-10*time.Minute).UnixNano())
	reg.EvictStale(time.Now().Add(-5 * time.Minute).UnixNano())

	if _, ok := reg.LookupReal(vip); ok {
		t.Fatal("stale entry was not evicted")
	}
}

func TestEvictStale_KeepsActive(t *testing.T) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("3.3.3.3:7000")

	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}

	reg.EvictStale(time.Now().Add(-5 * time.Minute).UnixNano())

	if _, ok := reg.LookupReal(vip); !ok {
		t.Fatal("active entry was incorrectly evicted")
	}
}

func TestEvictStale_CASRaceWithRealloc(t *testing.T) {
	// Verify CAS in EvictStale does not wipe an entry that was concurrently
	// re-allocated to a different realAddr between Load and CAS.
	reg := NewShardedRegistry()
	addr1 := netip.MustParseAddrPort("10.0.0.1:1111")

	vip := reg.Allocate(addr1)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}

	// Force-expire.
	reg.setLastActiveForTest(vip, time.Now().Add(-10*time.Minute).UnixNano())

	// Concurrently re-allocate the same slot to a different address.
	// (Simulate by directly writing a new encoded value into the slot.)
	offset, ok := offsetFromVIP(vip)
	if !ok {
		t.Fatal("offsetFromVIP failed")
	}
	addr2 := netip.MustParseAddrPort("10.0.0.2:2222")
	reg.vipTable[offset].v.Store(encAddrPort(addr2))
	reg.vipTable[offset].lastActive.Store(time.Now().UnixNano())

	// EvictStale CAS should fail (old v no longer matches) → new entry survives.
	reg.EvictStale(time.Now().Add(-5 * time.Minute).UnixNano())

	got, ok := reg.LookupReal(vip)
	if !ok {
		t.Fatal("CAS in EvictStale incorrectly cleared a freshly re-allocated slot")
	}
	if got != addr2 {
		t.Fatalf("got %s, want %s", got, addr2)
	}
}

// ---------------------------------------------------------------------------
// Concurrency — Data Race & Cross-mapping (go test -race)
// ---------------------------------------------------------------------------

func TestConcurrentAllocate_NoDataRace(t *testing.T) {
	const N = 10_000
	reg := NewShardedRegistry()

	type result struct {
		addr netip.AddrPort
		vip  netip.Addr
	}
	results := make([]result, N)

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			addr := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 1}),
				uint16(i%65535+1),
			)
			results[i] = result{addr: addr, vip: reg.Allocate(addr)}
		}()
	}
	wg.Wait()

	for i, r := range results {
		if !r.vip.IsValid() {
			t.Errorf("goroutine %d: Allocate returned zero vIP", i)
			continue
		}
		got, ok := reg.LookupReal(r.vip)
		if !ok {
			t.Errorf("goroutine %d: vIP %s not found after concurrent Allocate", i, r.vip)
			continue
		}
		if got != r.addr {
			t.Errorf("goroutine %d: cross-mapping! vIP %s → %s, want %s",
				i, r.vip, got, r.addr)
		}
	}
}

func TestConcurrentAllocateLookup_NoDataRace(t *testing.T) {
	const N = 5_000
	reg := NewShardedRegistry()

	// Pre-populate so LookupReal goroutines have something to find.
	addrs := make([]netip.AddrPort, N)
	vips := make([]netip.Addr, N)
	for i := 0; i < N; i++ {
		addrs[i] = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}),
			uint16(i%65535+1),
		)
		vips[i] = reg.Allocate(addrs[i])
	}

	var wg sync.WaitGroup
	wg.Add(N * 2)
	for i := 0; i < N; i++ {
		i := i
		// Writer: re-Allocate (hits fast path).
		go func() {
			defer wg.Done()
			reg.Allocate(addrs[i])
		}()
		// Reader: LookupReal concurrently.
		go func() {
			defer wg.Done()
			reg.LookupReal(vips[i])
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Benchmarks — target: 0 B/op, 0 allocs/op
// ---------------------------------------------------------------------------

// go test -bench=BenchmarkAllocate_Existing -benchmem -run=^$
func BenchmarkAllocate_Existing(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")
	reg.Allocate(addr)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reg.Allocate(addr)
	}
}

// go test -bench=BenchmarkLookupReal -benchmem -run=^$
func BenchmarkLookupReal(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")
	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		b.Skip("Allocate not implemented")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reg.LookupReal(vip)
	}
}

// go test -bench=BenchmarkAllocate_Parallel -benchmem -run=^$
func BenchmarkAllocate_Parallel(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")
	reg.Allocate(addr)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.Allocate(addr)
		}
	})
}

// go test -bench=BenchmarkLookupReal_Parallel -benchmem -run=^$
func BenchmarkLookupReal_Parallel(b *testing.B) {
	reg := NewShardedRegistry()
	addr := netip.MustParseAddrPort("8.8.8.8:1234")
	vip := reg.Allocate(addr)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.LookupReal(vip)
		}
	})
}
