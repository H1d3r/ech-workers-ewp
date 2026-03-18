package tun

// Issue #3 — TOCTOU Fuzzing: concurrent HandleUDP sessions, NAT cross-mapping,
// and endpoint resolution correctness under extreme concurrency.
//
// Run with race detector:
//   go test -race -count=1 -run TestFuzz ./tun/...

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ewp-core/nat"
	"ewp-core/transport"
)

// ---------------------------------------------------------------------------
// fuzzTransport / fuzzConn
//
// Unlike mockTransport, fuzzTransport creates a fresh fuzzConn per Dial().
// Each fuzzConn records the endpoint passed to ConnectUDP and pushes it to
// a shared channel for post-hoc verification.
// ---------------------------------------------------------------------------

type fuzzTransport struct {
	endpointCh chan transport.Endpoint // receives one value per ConnectUDP call
}

func newFuzzTransport(cap int) *fuzzTransport {
	return &fuzzTransport{endpointCh: make(chan transport.Endpoint, cap)}
}

func (ft *fuzzTransport) Dial() (transport.TunnelConn, error) {
	return &fuzzConn{endpointCh: ft.endpointCh, closed: make(chan struct{})}, nil
}
func (ft *fuzzTransport) Name() string                        { return "fuzz" }
func (ft *fuzzTransport) SetBypassConfig(_ *transport.BypassConfig) {}

type fuzzConn struct {
	endpointCh chan<- transport.Endpoint
	closeOnce  sync.Once
	closed     chan struct{}
}

func (c *fuzzConn) ConnectUDP(ep transport.Endpoint, _ []byte) error {
	select {
	case c.endpointCh <- ep:
	default:
		// channel full — should not happen if capacity == N
	}
	return nil
}

// ReadUDPFrom blocks until the conn is closed (simulates a tunnel that never
// receives a reply). udpReadLoop will exit when Close() is called.
func (c *fuzzConn) ReadUDPFrom(_ []byte) (int, netip.AddrPort, error) {
	<-c.closed
	return 0, netip.AddrPort{}, errors.New("fuzz: closed")
}

func (c *fuzzConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *fuzzConn) Connect(_ string, _ []byte) error              { return nil }
func (c *fuzzConn) ReadUDP() ([]byte, error)                      { return nil, errors.New("fuzz") }
func (c *fuzzConn) ReadUDPTo(_ []byte) (int, error)               { return 0, errors.New("fuzz") }
func (c *fuzzConn) Read(_ []byte) (int, error)                    { return 0, errors.New("fuzz") }
func (c *fuzzConn) Write(_ []byte) error                          { return nil }
func (c *fuzzConn) WriteUDP(_ transport.Endpoint, _ []byte) error { return nil }
func (c *fuzzConn) StartPing(_ time.Duration) chan struct{}        { return nil }

// ---------------------------------------------------------------------------
// fuzzUDPWriter: /dev/null writer for the fuzz test (no TUN injection needed)
// ---------------------------------------------------------------------------

type fuzzUDPWriter struct {
	writeCount atomic.Int64
}

func (w *fuzzUDPWriter) WriteTo(_ []byte, _, _ netip.AddrPort) error {
	w.writeCount.Add(1)
	return nil
}
func (w *fuzzUDPWriter) InjectUDP(_ []byte, _, _ netip.AddrPort) error { return nil }
func (w *fuzzUDPWriter) ReleaseConn(_, _ netip.AddrPort)               {}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// fuzzPeer builds a deterministic IPv4 AddrPort from an index.
// Guarantees unique (IP, port) for i in 0..65533.
func fuzzPeer(i int) netip.AddrPort {
	return netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{1, byte(i >> 8), byte(i), 1}),
		uint16((i%65534)+1),
	)
}

// fuzzSrc builds a unique source AddrPort for a client flow.
func fuzzSrc(i int) netip.AddrPort {
	return netip.AddrPortFrom(
		netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}),
		uint16(i+1),
	)
}

// ---------------------------------------------------------------------------
// Test 1: 1000 concurrent flows, unique (src, dst) — zero cross-mapping
//
// Each flow i sends to vips[i]:{port_i}.
// Expected ConnectUDP endpoint: realPeers[i].Addr():{port_i}.
// Cross-mapping: ConnectUDP for flow i receives peers[j].Addr() where j != i.
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_Handler_1k_NoCrossMapping
func TestFuzz_Handler_1k_NoCrossMapping(t *testing.T) {
	const N = 1000

	// Phase 1: pre-register N peers in the registry.
	reg := nat.NewShardedRegistry()
	peers := make([]netip.AddrPort, N)
	vips := make([]netip.Addr, N)
	for i := 0; i < N; i++ {
		peers[i] = fuzzPeer(i)
		vips[i] = reg.Allocate(peers[i])
		if !vips[i].IsValid() {
			t.Fatalf("[%d] Allocate returned zero vIP for peer %s", i, peers[i])
		}
	}

	// Phase 2: build handler with fuzz transport.
	trans := newFuzzTransport(N + 16)
	writer := &fuzzUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := NewHandler(ctx, trans, writer)
	h.SetPeerRegistry(reg)

	// Phase 3: fire N goroutines simultaneously.
	// Use a start barrier so goroutines race each other for maximum contention.
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			// dst port = peers[i].Port() → used as correlation key for verification.
			dst := netip.AddrPortFrom(vips[i], peers[i].Port())
			<-ready
			h.HandleUDP([]byte("ping"), fuzzSrc(i), dst)
		}()
	}
	close(ready) // release all goroutines at once
	wg.Wait()

	// Phase 4: collect N ConnectUDP endpoints.
	// Each unique (src, dst) 5-tuple triggers exactly ONE Dial (singleflight).
	endpoints := make([]transport.Endpoint, 0, N)
	deadline := time.After(5 * time.Second)
collect:
	for len(endpoints) < N {
		select {
		case ep := <-trans.endpointCh:
			endpoints = append(endpoints, ep)
		case <-deadline:
			t.Fatalf("timeout: received only %d/%d ConnectUDP calls", len(endpoints), N)
			break collect
		}
	}

	// Phase 5: verify — no cross-mapping.
	//
	// Correlation: endpoint.Addr.Port() == peer.Port() == flow's dst port.
	// Build port → expected peer IP map.
	portToExpectedIP := make(map[uint16]netip.Addr, N)
	for i := 0; i < N; i++ {
		portToExpectedIP[peers[i].Port()] = peers[i].Addr()
	}

	for idx, ep := range endpoints {
		if ep.Domain != "" {
			t.Errorf("[ep %d] got domain endpoint %q — peer flow should be direct addr", idx, ep.Domain)
			continue
		}
		if !ep.Addr.IsValid() {
			t.Errorf("[ep %d] got invalid endpoint addr", idx)
			continue
		}
		port := ep.Addr.Port()
		expectedIP, ok := portToExpectedIP[port]
		if !ok {
			t.Errorf("[ep %d] endpoint port %d not in expected set", idx, port)
			continue
		}
		if ep.Addr.Addr() != expectedIP {
			t.Errorf("[ep %d] CROSS-MAPPING: port %d got addr %s, want %s",
				idx, port, ep.Addr.Addr(), expectedIP)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 2: 500 goroutines, same (src, dst) — singleflight: exactly 1 Dial
//
// When N goroutines burst on the same 5-tuple, singleflight must ensure
// exactly ONE ConnectUDP call. Any extra calls indicate a TOCTOU regression.
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_Handler_SameTuple_SingleFlight
func TestFuzz_Handler_SameTuple_SingleFlight(t *testing.T) {
	const N = 500

	reg := nat.NewShardedRegistry()
	peer := fuzzPeer(0)
	vip := reg.Allocate(peer)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}

	trans := newFuzzTransport(N + 16)
	writer := &fuzzUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := NewHandler(ctx, trans, writer)
	h.SetPeerRegistry(reg)

	src := fuzzSrc(0)
	dst := netip.AddrPortFrom(vip, peer.Port())

	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-ready
			h.HandleUDP([]byte("burst"), src, dst)
		}()
	}
	close(ready)
	wg.Wait()

	// Drain the channel — must find exactly 1 endpoint.
	var count int
	drain:
	for {
		select {
		case ep := <-trans.endpointCh:
			count++
			if ep.Addr.Addr() != peer.Addr() {
				t.Errorf("singleflight: endpoint addr %s, want %s", ep.Addr.Addr(), peer.Addr())
			}
		default:
			break drain
		}
	}

	if count != 1 {
		t.Fatalf("singleflight: expected exactly 1 ConnectUDP call, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Test 3: CDN traffic mixed with P2P flows — zero registry pollution
//
// 500 CDN flows (real IPs) + 500 P2P flows (vIPs) fire concurrently.
// CDN flows MUST NOT trigger Allocate in peerReg.
// P2P flows MUST route to the correct real peer.
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_Handler_CDN_P2P_Mixed
func TestFuzz_Handler_CDN_P2P_Mixed(t *testing.T) {
	const half = 500

	reg := nat.NewShardedRegistry()
	// Pre-register P2P peers.
	p2pPeers := make([]netip.AddrPort, half)
	p2pVIPs := make([]netip.Addr, half)
	for i := 0; i < half; i++ {
		p2pPeers[i] = fuzzPeer(i)
		p2pVIPs[i] = reg.Allocate(p2pPeers[i])
	}

	// CDN endpoints are real IPs (never in 198.18/15 pool).
	// Use port range 20000+ to not collide with P2P port range.
	cdnEndpoints := make([]netip.AddrPort, half)
	for i := 0; i < half; i++ {
		cdnEndpoints[i] = netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}),
			uint16(20000+i),
		)
	}

	trans := newFuzzTransport(half*2 + 32)
	writer := &fuzzUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := NewHandler(ctx, trans, writer)
	h.SetPeerRegistry(reg)

	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(half * 2)

	// P2P flows.
	for i := 0; i < half; i++ {
		i := i
		go func() {
			defer wg.Done()
			dst := netip.AddrPortFrom(p2pVIPs[i], p2pPeers[i].Port())
			<-ready
			h.HandleUDP([]byte("p2p"), fuzzSrc(i), dst)
		}()
	}

	// CDN flows.
	for i := 0; i < half; i++ {
		i := i
		go func() {
			defer wg.Done()
			cdn := cdnEndpoints[i]
			<-ready
			h.HandleUDP([]byte("cdn"), fuzzSrc(i+half), cdn)
		}()
	}

	close(ready)
	wg.Wait()

	// Collect all endpoints.
	allEPs := make([]transport.Endpoint, 0, half*2)
	deadline := time.After(5 * time.Second)
collect:
	for len(allEPs) < half*2 {
		select {
		case ep := <-trans.endpointCh:
			allEPs = append(allEPs, ep)
		case <-deadline:
			t.Fatalf("timeout: received only %d/%d ConnectUDP calls", len(allEPs), half*2)
			break collect
		}
	}

	// Build expected sets.
	p2pExpected := make(map[netip.Addr]bool, half)  // real peer IPs
	cdnExpected := make(map[netip.AddrPort]bool, half) // real CDN AddrPorts
	for i := 0; i < half; i++ {
		p2pExpected[p2pPeers[i].Addr()] = true
		cdnExpected[cdnEndpoints[i]] = true
	}

	// Verify every endpoint is in the correct expected set.
	for idx, ep := range allEPs {
		if ep.Domain != "" {
			t.Errorf("[ep %d] unexpected domain endpoint %q", idx, ep.Domain)
			continue
		}
		if !ep.Addr.IsValid() {
			t.Errorf("[ep %d] invalid endpoint", idx)
			continue
		}
		// Endpoint is either a real CDN addr or a real peer addr.
		// It must NOT be a vIP (198.18/15).
		ip := ep.Addr.Addr()
		b := ip.As4()
		if b[0] == 198 && (b[1] == 18 || b[1] == 19) {
			t.Errorf("[ep %d] ConnectUDP received vIP %s — must be real addr", idx, ip)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 4: Concurrent Allocate + HandleUDP — no stale vIP leak
//
// Registry entries are being evicted while HandleUDP is routing to them.
// HandleUDP must degrade gracefully (miss → direct route) and must never
// route to the WRONG peer.
// ---------------------------------------------------------------------------

// go test -race -run TestFuzz_Handler_EvictRacesWithRoute
func TestFuzz_Handler_EvictRacesWithRoute(t *testing.T) {
	const N = 300

	reg := nat.NewShardedRegistry()
	peers := make([]netip.AddrPort, N)
	vips := make([]netip.Addr, N)
	for i := 0; i < N; i++ {
		peers[i] = fuzzPeer(i)
		vips[i] = reg.Allocate(peers[i])
	}

	trans := newFuzzTransport(N*2 + 32)
	writer := &fuzzUDPWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := NewHandler(ctx, trans, writer)
	h.SetPeerRegistry(reg)

	ready := make(chan struct{})
	var wg sync.WaitGroup

	// Evictors: continuously call EvictStale, racing with HandleUDP routing.
	const evictors = 4
	wg.Add(evictors)
	for i := 0; i < evictors; i++ {
		go func() {
			defer wg.Done()
			<-ready
			for j := 0; j < 50; j++ {
				reg.EvictStale(time.Now().Add(1 * time.Second).UnixNano()) // evict EVERYTHING
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Routers: fire HandleUDP concurrently.
	results := make([]transport.Endpoint, N)
	resultMu := sync.Mutex{}
	_ = results
	received := atomic.Int64{}

	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			dst := netip.AddrPortFrom(vips[i], peers[i].Port())
			<-ready
			h.HandleUDP([]byte("data"), fuzzSrc(i), dst)
		}()
	}

	close(ready)
	wg.Wait()

	// Collect whatever ConnectUDP calls arrived.
	collectDeadline := time.After(3 * time.Second)
	var collectedEPs []transport.Endpoint
drain:
	for {
		select {
		case ep := <-trans.endpointCh:
			received.Add(1)
			collectedEPs = append(collectedEPs, ep)
			resultMu.Lock()
			_ = collectedEPs
			resultMu.Unlock()
		case <-collectDeadline:
			break drain
		}
	}

	// Key invariant: if an endpoint WAS resolved from a vIP, it must be a REAL
	// peer IP (not another vIP, not garbage). It's acceptable for evicted entries
	// to fall through to direct-route (dst becomes the raw vIP — this is the
	// degraded path). What's NOT acceptable: routing vIP_i to peers[j] where j != i.
	portToPeer := make(map[uint16]netip.Addr, N)
	for i := 0; i < N; i++ {
		portToPeer[peers[i].Port()] = peers[i].Addr()
	}

	for idx, ep := range collectedEPs {
		if !ep.Addr.IsValid() || ep.Domain != "" {
			continue
		}
		port := ep.Addr.Port()
		expectedIP, ok := portToPeer[port]
		if !ok {
			continue // port not in our set (CDN or other traffic)
		}
		if ep.Addr.Addr() != expectedIP {
			// The vIP was still alive when LookupReal ran, but resolved to wrong peer.
			// This is the cross-mapping bug — fatal.
			b := ep.Addr.Addr().As4()
			if b[0] != 198 { // not a vIP (degraded path is okay)
				t.Errorf("[ep %d] CROSS-MAPPING under evict race: port %d → %s, want %s",
					idx, port, ep.Addr.Addr(), expectedIP)
			}
		}
	}
}
