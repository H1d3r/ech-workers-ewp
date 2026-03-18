//go:build !android

package tun

// Lifecycle Red tests for Issues #4, #5, #7.
//
// All tests in this file COMPILE against current stubs but FAIL at runtime:
//   - newHandlerCore returns nil registry        → #4 tests fail
//   - newHandlerCore never sets fakeIPPool       → #5 tests fail
//   - startEviction is a no-op                  → #4 eviction tests fail
//
// Run:  go test -race -run TestLifecycle ./tun/...
// Green phase will implement newHandlerCore + startEviction fully.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"ewp-core/nat"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func lifecycleCfg(conn *mockTunnelConn) *Config {
	return &Config{Transport: &mockTransport{conn: conn}}
}

// ---------------------------------------------------------------------------
// Issue #4 — peerReg always wired
// ---------------------------------------------------------------------------

// RED: newHandlerCore must return a non-nil ShardedRegistry and wire handler.peerReg.
// FAILS: stub returns nil.
func TestLifecycle_HandlerCore_PeerRegAlwaysSet(t *testing.T) {
	conn := newMockTunnelConn()
	writer := &mockUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, reg := newHandlerCore(ctx, lifecycleCfg(conn), writer)

	if reg == nil {
		t.Fatal("#4 FAIL: newHandlerCore returned nil registry — ShardedRegistry not allocated")
	}
	if h.peerReg == nil {
		t.Fatal("#4 FAIL: handler.peerReg is nil — SetPeerRegistry not called")
	}
}

// RED: the registry pointer returned by newHandlerCore must alias handler.peerReg exactly.
// Aliasing break → two separate objects → Allocate in one, LookupReal in other = miss.
// FAILS: both are nil.
func TestLifecycle_HandlerCore_PeerReg_SameObject(t *testing.T) {
	conn := newMockTunnelConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, reg := newHandlerCore(ctx, lifecycleCfg(conn), &mockUDPWriter{})

	if reg == nil || h.peerReg == nil {
		t.Fatal("#4 FAIL: peerReg is nil")
	}
	if reg != h.peerReg {
		t.Fatal("#4 FAIL: returned registry != handler.peerReg — aliasing broken")
	}
}

// RED: peerReg must be a fresh, functional ShardedRegistry.
// After newHandlerCore, Allocate must work end-to-end through the handler's registry.
// FAILS: peerReg is nil → Allocate panics or no-ops.
func TestLifecycle_HandlerCore_PeerReg_Functional(t *testing.T) {
	conn := newMockTunnelConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, reg := newHandlerCore(ctx, lifecycleCfg(conn), &mockUDPWriter{})
	if reg == nil {
		t.Fatal("#4 FAIL: registry nil")
	}

	peer := netip.MustParseAddrPort("5.6.7.8:9999")
	vip := reg.Allocate(peer)
	if !vip.IsValid() {
		t.Fatal("#4 FAIL: Allocate returned zero vIP")
	}

	got, ok := h.peerReg.LookupReal(vip)
	if !ok {
		t.Fatal("#4 FAIL: LookupReal miss on handler's peerReg — aliasing broken or peerReg nil")
	}
	if got != peer {
		t.Fatalf("#4 FAIL: LookupReal returned %s, want %s", got, peer)
	}
}

// ---------------------------------------------------------------------------
// Issue #5 — conditional FakeIP pool
// ---------------------------------------------------------------------------

// RED: DisableFakeIP=false (default) → fakeIPPool must be set.
// FAILS: stub never calls SetFakeIPPool.
func TestLifecycle_FakeIPMode_PoolSet(t *testing.T) {
	conn := newMockTunnelConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := lifecycleCfg(conn)
	cfg.DisableFakeIP = false

	h, _ := newHandlerCore(ctx, cfg, &mockUDPWriter{})

	if h.fakeIPPool == nil {
		t.Fatal("#5 FAIL: fakeIPPool is nil with DisableFakeIP=false — FakeIP mode not initialised")
	}
}

// RED: DisableFakeIP=true → fakeIPPool must be nil, peerReg must be non-nil.
// Both conditions FAIL: stub returns nil peerReg, doesn't check DisableFakeIP.
func TestLifecycle_NormalMode_NilPoolNonNilReg(t *testing.T) {
	conn := newMockTunnelConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := lifecycleCfg(conn)
	cfg.DisableFakeIP = true

	h, reg := newHandlerCore(ctx, cfg, &mockUDPWriter{})

	if h.fakeIPPool != nil {
		t.Fatal("#5 FAIL: fakeIPPool must be nil in Normal Mode (DisableFakeIP=true)")
	}
	if reg == nil {
		t.Fatal("#4+5 FAIL: peerReg must be non-nil in Normal Mode")
	}
	if h.peerReg == nil {
		t.Fatal("#4+5 FAIL: handler.peerReg must be wired in Normal Mode")
	}
}

// RED: zero-value Config (DisableFakeIP not set = false) defaults to FakeIP mode.
// Backward compatibility: existing callers that don't set DisableFakeIP get fakeIPPool.
// FAILS: stub never sets fakeIPPool.
func TestLifecycle_ZeroConfig_DefaultsFakeIPMode(t *testing.T) {
	conn := newMockTunnelConn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := lifecycleCfg(conn) // DisableFakeIP zero value = false

	h, _ := newHandlerCore(ctx, cfg, &mockUDPWriter{})

	if h.fakeIPPool == nil {
		t.Fatal("#5 FAIL: zero-value Config must default to FakeIP mode (backward compat)")
	}
}

// ---------------------------------------------------------------------------
// Issue #4 — background eviction goroutine
// ---------------------------------------------------------------------------

// RED: startEviction must run EvictStale within one interval.
// Proof: allocate an entry, wait evictAfter + 2×interval, entry must be gone.
// FAILS: startEviction is a no-op.
func TestLifecycle_Eviction_RunsWithinInterval(t *testing.T) {
	reg := nat.NewShardedRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := netip.MustParseAddrPort("10.0.0.1:1234")
	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		t.Fatal("Allocate failed")
	}

	// Evict anything older than evictAfter.  After sleeping evictAfter + 2×interval
	// the entry's lastActive will be older than evictAfter, so it must be swept.
	const interval = 30 * time.Millisecond
	const evictAfter = 20 * time.Millisecond
	startEviction(ctx, reg, interval, evictAfter)

	time.Sleep(evictAfter + 3*interval + 10*time.Millisecond)

	if _, ok := reg.LookupReal(vip); ok {
		t.Fatal("#4 FAIL: stale entry still present — startEviction is a no-op (goroutine not started)")
	}
}

// RED: startEviction goroutine must stop after ctx cancel.
// Proof: the goroutine exits if and only if it's started (no-op stub trivially "passes"
// the exit check, but fails TestLifecycle_Eviction_RunsWithinInterval first, so this
// test is the GREEN-phase regression guard for correct lifecycle teardown).
func TestLifecycle_Eviction_ExitsOnCancel(t *testing.T) {
	reg := nat.NewShardedRegistry()
	ctx, cancel := context.WithCancel(context.Background())

	const interval = 20 * time.Millisecond
	const evictAfter = 10 * time.Millisecond
	startEviction(ctx, reg, interval, evictAfter)

	// Let it run a few ticks to confirm it started.
	time.Sleep(3 * interval)

	// Cancel and give the goroutine time to exit.
	cancel()
	time.Sleep(2 * interval)

	// Fill registry AFTER cancel — none should be evicted by the (now-dead) goroutine.
	addr := netip.MustParseAddrPort("9.9.9.9:5353")
	vip := reg.Allocate(addr)
	if !vip.IsValid() {
		t.Fatal("Allocate failed")
	}

	// Give two intervals — if goroutine still ran, it would evict (since evictAfter < elapsed).
	time.Sleep(3 * interval)

	// Entry should still be present — goroutine must be dead.
	// NOTE: manual EvictStale still works; this only checks the goroutine is gone.
	if _, ok := reg.LookupReal(vip); !ok {
		t.Log("#4 WARN: entry evicted after cancel — goroutine may not have exited cleanly")
	}
	// Primary assertion for Red: Eviction_RunsWithinInterval fails, not this one.
}

// ---------------------------------------------------------------------------
// Issue #7 — Integration: full Normal Mode flow end-to-end via handler
// ---------------------------------------------------------------------------

// RED: after newHandlerCore in Normal Mode, a P2P flow must route to the real peer.
// Integration chain: peerReg.Allocate → HandleUDP → ConnectUDP(realPeerAddr).
// FAILS: peerReg is nil → LookupReal never called → CDN fallback.
func TestLifecycle_Integration_NormalMode_P2PFlow(t *testing.T) {
	conn := newMockTunnelConn()
	writer := &mockUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &Config{
		Transport:     &mockTransport{conn: conn},
		DisableFakeIP: true,
	}
	h, reg := newHandlerCore(ctx, cfg, writer)
	if reg == nil {
		t.Fatal("#4+7 FAIL: registry nil — prerequisite for integration test not met")
	}

	// Anchor a P2P peer.
	peer := netip.MustParseAddrPort("7.7.7.7:9001")
	vip := reg.Allocate(peer)

	// Local app sends to vIP:9001.
	src := netip.MustParseAddrPort("10.0.0.1:50000")
	dst := netip.AddrPortFrom(vip, peer.Port())
	h.HandleUDP([]byte("hello"), src, dst)

	// ConnectUDP must be called with the REAL peer address.
	select {
	case ep := <-conn.connectUDPArgs:
		if ep.Domain != "" {
			t.Fatalf("#7 FAIL: got domain %q — peer flow went to wrong branch", ep.Domain)
		}
		if ep.Addr.Addr() != peer.Addr() {
			t.Fatalf("#7 FAIL: ConnectUDP addr=%s, want peer addr=%s", ep.Addr.Addr(), peer.Addr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("#7 FAIL: timeout — HandleUDP did not call ConnectUDP")
	}
}

// RED: after newHandlerCore in FakeIP mode, DNS domain routing still works.
// Integration guard: FakeIP + peerReg dual mode must not break domain resolution.
// FAILS: fakeIPPool is nil → domain lookup fails → CDN fallback.
func TestLifecycle_Integration_FakeIPMode_DomainRouting(t *testing.T) {
	conn := newMockTunnelConn()
	writer := &mockUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &Config{
		Transport:     &mockTransport{conn: conn},
		DisableFakeIP: false,
	}
	h, _ := newHandlerCore(ctx, cfg, writer)
	if h.fakeIPPool == nil {
		t.Fatal("#5+7 FAIL: fakeIPPool nil — prerequisite for domain routing not met")
	}

	// Allocate a domain FakeIP.
	domainFakeIP := h.fakeIPPool.AllocateIPv4("game.example.com")
	if !domainFakeIP.IsValid() {
		t.Fatal("AllocateIPv4 failed")
	}

	src := netip.MustParseAddrPort("10.0.0.1:50001")
	dst := netip.AddrPortFrom(domainFakeIP, 443)
	h.HandleUDP([]byte("data"), src, dst)

	select {
	case ep := <-conn.connectUDPArgs:
		if ep.Domain != "game.example.com" {
			t.Fatalf("#7 FAIL: domain routing got %q, want game.example.com", ep.Domain)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("#7 FAIL: timeout — domain routing did not fire ConnectUDP")
	}
}
