package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"ewp-core/dns"
	"ewp-core/nat"
	"ewp-core/transport"
)

// ---------------------------------------------------------------------------
// Mock: transport.TunnelConn
// ---------------------------------------------------------------------------

type mockTunnelConn struct {
	// connectUDPArgs receives the Endpoint passed to ConnectUDP.
	connectUDPArgs chan transport.Endpoint

	// inbound is the queue of packets that ReadUDPFrom will deliver.
	// Close the channel to make ReadUDPFrom return an error (EOF).
	inbound chan inboundPacket

	closeOnce sync.Once
	closed    chan struct{}
}

type inboundPacket struct {
	data       []byte
	remoteAddr netip.AddrPort
}

func newMockTunnelConn() *mockTunnelConn {
	return &mockTunnelConn{
		connectUDPArgs: make(chan transport.Endpoint, 1),
		inbound:        make(chan inboundPacket, 8),
		closed:         make(chan struct{}),
	}
}

func (m *mockTunnelConn) ConnectUDP(target transport.Endpoint, _ []byte) error {
	select {
	case m.connectUDPArgs <- target:
	default:
	}
	return nil
}
func (m *mockTunnelConn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	select {
	case pkt, ok := <-m.inbound:
		if !ok {
			return 0, netip.AddrPort{}, errors.New("mock: closed")
		}
		n := copy(buf, pkt.data)
		return n, pkt.remoteAddr, nil
	case <-m.closed:
		return 0, netip.AddrPort{}, errors.New("mock: closed")
	}
}
func (m *mockTunnelConn) WriteUDP(_ transport.Endpoint, _ []byte) error { return nil }
func (m *mockTunnelConn) Connect(_ string, _ []byte) error               { return nil }
func (m *mockTunnelConn) ReadUDP() ([]byte, error)                       { return nil, errors.New("mock") }
func (m *mockTunnelConn) ReadUDPTo(buf []byte) (int, error)              { return 0, errors.New("mock") }
func (m *mockTunnelConn) Read(buf []byte) (int, error)                   { return 0, errors.New("mock") }
func (m *mockTunnelConn) Write(_ []byte) error                           { return nil }
func (m *mockTunnelConn) StartPing(_ time.Duration) chan struct{}         { return nil }
func (m *mockTunnelConn) Close() error {
	m.closeOnce.Do(func() { close(m.closed) })
	return nil
}

// ---------------------------------------------------------------------------
// Mock: transport.Transport
// ---------------------------------------------------------------------------

type mockTransport struct {
	conn *mockTunnelConn
}

func (m *mockTransport) Dial() (transport.TunnelConn, error) { return m.conn, nil }
func (m *mockTransport) Name() string                        { return "mock" }
func (m *mockTransport) SetBypassConfig(_ *transport.BypassConfig) {}

// ---------------------------------------------------------------------------
// Mock: UDPWriter
// ---------------------------------------------------------------------------

type mockUDPWriter struct {
	mu       sync.Mutex
	writes   []writeCall
	injected []writeCall
}

type writeCall struct {
	payload []byte
	src     netip.AddrPort
	dst     netip.AddrPort
}

func (w *mockUDPWriter) WriteTo(p []byte, src, dst netip.AddrPort) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	w.writes = append(w.writes, writeCall{cp, src, dst})
	return nil
}
func (w *mockUDPWriter) InjectUDP(p []byte, src, dst netip.AddrPort) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	w.injected = append(w.injected, writeCall{cp, src, dst})
	return nil
}
func (w *mockUDPWriter) ReleaseConn(_, _ netip.AddrPort) {}

func (w *mockUDPWriter) firstWrite() (writeCall, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.writes) == 0 {
		return writeCall{}, false
	}
	return w.writes[0], true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestHandler(t *testing.T, conn *mockTunnelConn) (*Handler, *mockUDPWriter) {
	t.Helper()
	writer := &mockUDPWriter{}
	trans := &mockTransport{conn: conn}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := NewHandler(ctx, trans, writer)
	return h, writer
}

// waitConnectUDP blocks until ConnectUDP is called on conn or timeout expires.
func waitConnectUDP(t *testing.T, conn *mockTunnelConn) transport.Endpoint {
	t.Helper()
	select {
	case ep := <-conn.connectUDPArgs:
		return ep
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ConnectUDP")
		return transport.Endpoint{}
	}
}

// ---------------------------------------------------------------------------
// Issue #2 — Test Suite
// ---------------------------------------------------------------------------

// RED: passes already (CDN direct-route was always the fallback path).
// Remains as a non-regression guard after Green phase refactoring.
func TestHandleUDP_CDNTraffic_BypassesPeerReg(t *testing.T) {
	conn := newMockTunnelConn()
	h, _ := newTestHandler(t, conn)

	reg := nat.NewShardedRegistry()
	h.SetPeerRegistry(reg)
	// No fakeIPPool — Normal Mode.

	src := netip.MustParseAddrPort("10.0.0.1:55000")
	dst := netip.MustParseAddrPort("1.1.1.1:443") // CDN, real IP
	payload := []byte("QUIC-initial")

	h.HandleUDP(payload, src, dst)

	ep := waitConnectUDP(t, conn)

	// CDN traffic must route directly to the real IP, no vIP translation.
	if ep.Domain != "" {
		t.Fatalf("CDN traffic got domain endpoint %q, want direct IP", ep.Domain)
	}
	if ep.Addr != dst {
		t.Fatalf("CDN endpoint: got %s, want %s", ep.Addr, dst)
	}

	// PeerRegistry must remain empty — no Allocate was called for CDN traffic.
	if _, ok := reg.LookupReal(netip.MustParseAddr("198.18.0.1")); ok {
		t.Fatal("PeerRegistry was mutated for CDN traffic")
	}
}

// RED: fails in Red phase because peerReg lookup not wired into HandleUDP yet.
// Green: ConnectUDP must receive the real peer address, not the vIP.
func TestHandleUDP_PeerVIP_RoutesToRealAddr(t *testing.T) {
	conn := newMockTunnelConn()
	h, _ := newTestHandler(t, conn)

	reg := nat.NewShardedRegistry()
	h.SetPeerRegistry(reg)

	// Pre-anchor a real peer to a vIP (simulates an inbound P2P packet already seen).
	realPeer := netip.MustParseAddrPort("5.6.7.8:9999")
	vip := reg.Allocate(realPeer)
	if !vip.IsValid() {
		t.Fatal("Allocate returned zero vIP")
	}

	// App sends UDP to the vIP (replying to the P2P peer).
	src := netip.MustParseAddrPort("10.0.0.1:55001")
	dst := netip.AddrPortFrom(vip, realPeer.Port())
	h.HandleUDP([]byte("pong"), src, dst)

	ep := waitConnectUDP(t, conn)

	// ConnectUDP must be called with the REAL peer address, not the vIP.
	if ep.Domain != "" {
		t.Fatalf("got domain endpoint %q, want direct addr", ep.Domain)
	}
	wantAddr := netip.AddrPortFrom(realPeer.Addr(), dst.Port())
	if ep.Addr != wantAddr {
		t.Fatalf("P2P routing: got %s, want %s", ep.Addr, wantAddr)
	}
}

// RED: depends on fakeIPPool DNS domain reverse-lookup; unchanged by Issue #2.
// Included as a regression guard — must still pass after Green phase wiring.
func TestHandleUDP_FakeIPMode_DomainRouting(t *testing.T) {
	conn := newMockTunnelConn()
	h, _ := newTestHandler(t, conn)

	pool := dns.NewFakeIPPool()
	h.SetFakeIPPool(pool)
	// No peerReg — legacy FakeIP-only mode.

	domainFakeIP := pool.AllocateIPv4("example.com")
	if !domainFakeIP.IsValid() {
		t.Fatal("AllocateIPv4 returned zero")
	}

	src := netip.MustParseAddrPort("10.0.0.1:55002")
	dst := netip.AddrPortFrom(domainFakeIP, 443)
	h.HandleUDP([]byte("data"), src, dst)

	ep := waitConnectUDP(t, conn)

	if ep.Domain != "example.com" {
		t.Fatalf("domain routing: got domain=%q, want %q", ep.Domain, "example.com")
	}
	if ep.Port != 443 {
		t.Fatalf("domain routing: got port=%d, want 443", ep.Port)
	}
}

// RED: fails because udpReadLoop still uses fakeIPPool (nil here) for peer injection.
// Green: peer packet injected with vIP as src, not the real IP.
func TestUDPReadLoop_NewPeerSrc_AllocatesVIP(t *testing.T) {
	conn := newMockTunnelConn()
	h, writer := newTestHandler(t, conn)

	reg := nat.NewShardedRegistry()
	h.SetPeerRegistry(reg)

	// Establish a session: app sends to server 1.2.3.4:3478.
	src := netip.MustParseAddrPort("10.0.0.1:55003")
	server := netip.MustParseAddrPort("1.2.3.4:3478")
	h.HandleUDP([]byte("stun-req"), src, server)
	waitConnectUDP(t, conn) // drain — session is now up

	// Proxy delivers first packet FROM the known server (sets serverRealIP).
	conn.inbound <- inboundPacket{
		data:       []byte("stun-resp"),
		remoteAddr: server,
	}
	// Proxy delivers second packet FROM a NEW source (P2P peer).
	peerAddr := netip.MustParseAddrPort("5.6.7.8:9999")
	conn.inbound <- inboundPacket{
		data:       []byte("peer-data"),
		remoteAddr: peerAddr,
	}
	// Signal end of stream.
	close(conn.inbound)

	// Wait for udpReadLoop to process both packets.
	deadline := time.Now().Add(2 * time.Second)
	var peerWrite writeCall
	for time.Now().Before(deadline) {
		writer.mu.Lock()
		n := len(writer.writes)
		if n >= 2 {
			peerWrite = writer.writes[1]
			writer.mu.Unlock()
			break
		}
		writer.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	if peerWrite.src == (netip.AddrPort{}) {
		t.Fatal("udpReadLoop did not inject two packets within deadline")
	}

	// The peer packet src must be a vIP (198.18.x.x), NOT the real peer IP.
	srcIP := peerWrite.src.Addr()
	if srcIP == peerAddr.Addr() {
		t.Fatalf("peer packet injected with real IP %s — vIP not allocated", srcIP)
	}
	if srcIP.As4()[0] != 198 {
		t.Fatalf("peer packet src %s is not in 198.18/15 vIP pool", srcIP)
	}

	// PeerRegistry must map the vIP back to the real peer address.
	gotReal, ok := reg.LookupReal(srcIP)
	if !ok {
		t.Fatalf("peerReg.LookupReal(%s) returned false — vIP not anchored", srcIP)
	}
	wantReal := netip.AddrPortFrom(peerAddr.Addr(), peerAddr.Port())
	if gotReal != wantReal {
		t.Fatalf("peerReg.LookupReal: got %s, want %s", gotReal, wantReal)
	}
}

// RED: normal server CDN → all replies from same IP → peerReg must stay empty.
func TestUDPReadLoop_KnownServerSrc_NoPeerAlloc(t *testing.T) {
	conn := newMockTunnelConn()
	h, writer := newTestHandler(t, conn)

	reg := nat.NewShardedRegistry()
	h.SetPeerRegistry(reg)

	src := netip.MustParseAddrPort("10.0.0.1:55004")
	cdn := netip.MustParseAddrPort("104.16.0.0:443")
	h.HandleUDP([]byte("quic-init"), src, cdn)
	waitConnectUDP(t, conn)

	// Three replies all from the same CDN server — none should trigger Allocate.
	for i := 0; i < 3; i++ {
		conn.inbound <- inboundPacket{data: []byte("cdn-data"), remoteAddr: cdn}
	}
	close(conn.inbound)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		writer.mu.Lock()
		n := len(writer.writes)
		writer.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Walk vIP space: none should be occupied.
	for _, checkIP := range []string{"198.18.0.1", "198.18.0.2", "198.18.0.3"} {
		if _, ok := reg.LookupReal(netip.MustParseAddr(checkIP)); ok {
			t.Fatalf("PeerRegistry allocated vIP for CDN-only traffic (%s occupied)", checkIP)
		}
	}
}

// RED: when BOTH fakeIPPool (DNS mode) and peerReg are set, domain FakeIPs take
// priority; peer vIPs are served by peerReg. No cross-contamination.
func TestHandleUDP_DualMode_DomainBeforePeer(t *testing.T) {
	conn := newMockTunnelConn()
	h, _ := newTestHandler(t, conn)

	pool := dns.NewFakeIPPool()
	h.SetFakeIPPool(pool)
	reg := nat.NewShardedRegistry()
	h.SetPeerRegistry(reg)

	// Allocate domain FakeIP via pool (DNS FakeIP path).
	domainIP := pool.AllocateIPv4("api.example.com")

	// Allocate peer vIP via peerReg (P2P peer path).
	realPeer := netip.MustParseAddrPort("9.9.9.9:5555")
	peerVIP := reg.Allocate(realPeer)

	// Domain FakeIP → domain endpoint.
	src := netip.MustParseAddrPort("10.0.0.1:60000")
	h.HandleUDP([]byte("d"), src, netip.AddrPortFrom(domainIP, 443))
	ep := waitConnectUDP(t, conn)
	if ep.Domain != "api.example.com" {
		t.Fatalf("domain path: got %q, want api.example.com", ep.Domain)
	}

	// Peer vIP → real peer addr (new session, different src port).
	conn2 := newMockTunnelConn()
	trans2 := &mockTransport{conn: conn2}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	h2 := NewHandler(ctx2, trans2, &mockUDPWriter{})
	h2.SetFakeIPPool(pool)
	h2.SetPeerRegistry(reg)

	src2 := netip.MustParseAddrPort("10.0.0.2:60001")
	h2.HandleUDP([]byte("p"), src2, netip.AddrPortFrom(peerVIP, 5555))
	ep2 := waitConnectUDP(t, conn2)
	if ep2.Domain != "" {
		t.Fatalf("peer path got domain %q, want direct addr", ep2.Domain)
	}
	if ep2.Addr.Addr() != realPeer.Addr() {
		t.Fatalf("peer path: got %s, want real peer IP %s", ep2.Addr, realPeer.Addr())
	}
}
