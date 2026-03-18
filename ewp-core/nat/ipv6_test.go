package nat

// Issue #6 — IPv6 peer handling.
//
// Design decision: the flat [131070]PeerEntry array encodes peers as packed uint64
// (8 bytes). IPv6 addresses are 16 bytes and cannot be packed without pointer
// fields (which would break the GC no-scan invariant). Therefore:
//
//   - IPv4 peers: full support via ShardedRegistry.
//   - IPv6 peers: rejected at the Allocate boundary; droppedIPv6 counter incremented.
//
// Tests in this file COMPILE against current stubs and:
//   - TestIPv6_Allocate_ReturnsZero          → PASSES  (current behavior, regression guard)
//   - TestIPv6_Allocate_IncrementsDropCounter → FAILS   (stub DroppedIPv6Count always 0)
//   - TestIPv6_DropCounter_Concurrent        → FAILS   (counter never incremented)
//   - TestIPv6_DropCounter_IPv4Unaffected    → PASSES  (IPv4 path unchanged, regression guard)

import (
	"net/netip"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Regression guard — existing behavior must not regress
// ---------------------------------------------------------------------------

// RED-PASS: Allocate(IPv6 AddrPort) must return zero addr (already does).
func TestIPv6_Allocate_ReturnsZero(t *testing.T) {
	reg := NewShardedRegistry()
	ipv6Peer := netip.MustParseAddrPort("[2001:db8::1]:9001")

	vip := reg.Allocate(ipv6Peer)
	if vip.IsValid() {
		t.Fatalf("Allocate(IPv6) returned non-zero vIP %s — must return zero", vip)
	}
}

// RED-PASS: IPv4 peers unaffected by IPv6 drop logic.
func TestIPv6_DropCounter_IPv4Unaffected(t *testing.T) {
	reg := NewShardedRegistry()
	ipv4Peer := netip.MustParseAddrPort("1.2.3.4:5678")

	vip := reg.Allocate(ipv4Peer)
	if !vip.IsValid() {
		t.Fatal("Allocate(IPv4) returned zero vIP — IPv4 path broken")
	}
	if reg.DroppedIPv6Count() != 0 {
		t.Fatalf("DroppedIPv6Count = %d after IPv4 Allocate, want 0",
			reg.DroppedIPv6Count())
	}
}

// ---------------------------------------------------------------------------
// New behaviour — counter increment
// ---------------------------------------------------------------------------

// RED-FAIL: each Allocate(IPv6) must increment droppedIPv6 by 1.
// FAILS: Allocate does not call droppedIPv6.Add(1); DroppedIPv6Count returns 0.
func TestIPv6_Allocate_IncrementsDropCounter(t *testing.T) {
	reg := NewShardedRegistry()
	ipv6Peers := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::1]:9001"),
		netip.MustParseAddrPort("[2001:db8::2]:9002"),
		netip.MustParseAddrPort("[::1]:53"),
	}

	for i, peer := range ipv6Peers {
		reg.Allocate(peer)
		want := int64(i + 1)
		if got := reg.DroppedIPv6Count(); got != want {
			t.Fatalf("after %d IPv6 Allocate calls: DroppedIPv6Count=%d, want %d (Issue #6)",
				i+1, got, want)
		}
	}
}

// RED-FAIL: counter must be safe under concurrent IPv6 Allocate calls.
// FAILS: counter is never incremented.
func TestIPv6_DropCounter_Concurrent(t *testing.T) {
	const N = 1000
	reg := NewShardedRegistry()
	peer := netip.MustParseAddrPort("[2001:db8::1]:9001")

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			reg.Allocate(peer)
		}()
	}
	wg.Wait()

	if got := reg.DroppedIPv6Count(); got != N {
		t.Fatalf("concurrent IPv6: DroppedIPv6Count=%d, want %d (Issue #6)", got, N)
	}
}

// RED-FAIL: Allocate(IPv6-mapped-IPv4) must be treated as IPv4 (not dropped).
// e.g. ::ffff:1.2.3.4 is a real IPv4 peer arriving via IPv6 socket — must not drop.
// FAILS: current code checks Is4() before Unmap(); ::ffff:x.x.x.x is NOT Is4().
// Wait — actually Allocate already calls Unmap() first. Let's verify this is correct.
func TestIPv6_IPv4MappedIPv6_TreatedAsIPv4(t *testing.T) {
	reg := NewShardedRegistry()
	// ::ffff:5.6.7.8 is an IPv4-mapped IPv6 address.
	// Allocate must Unmap() it to 5.6.7.8 and treat it as IPv4.
	mapped := netip.MustParseAddrPort("[::ffff:5.6.7.8]:1234")

	vip := reg.Allocate(mapped)
	if !vip.IsValid() {
		t.Fatal("#6 FAIL: IPv4-mapped IPv6 peer was dropped — must be treated as IPv4 after Unmap()")
	}

	// Must NOT count as a dropped IPv6 peer.
	if reg.DroppedIPv6Count() != 0 {
		t.Fatalf("#6 FAIL: IPv4-mapped peer counted as IPv6 drop (count=%d), want 0",
			reg.DroppedIPv6Count())
	}

	// Lookup must work.
	want := netip.MustParseAddrPort("5.6.7.8:1234") // unmapped
	got, ok := reg.LookupReal(vip)
	if !ok {
		t.Fatalf("LookupReal(%s) returned false", vip)
	}
	if got != want {
		t.Fatalf("LookupReal: got %s, want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Idempotency — repeated IPv6 Allocate for the same peer counts each call
// ---------------------------------------------------------------------------

// RED-FAIL: each call is a separate drop event, even for the same peer.
func TestIPv6_SamePeer_CountsEachCall(t *testing.T) {
	const calls = 5
	reg := NewShardedRegistry()
	peer := netip.MustParseAddrPort("[::1]:80")

	for i := 0; i < calls; i++ {
		reg.Allocate(peer)
	}

	if got := reg.DroppedIPv6Count(); got != calls {
		t.Fatalf("same IPv6 peer, %d calls: count=%d, want %d", calls, got, calls)
	}
}
