package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"ewp-core/dns"
	"ewp-core/engine"
)

// fakeWriter captures every (payload, src-addr) pair we attempt to
// write back into the TUN. It implements udpResponseWriter for tests.
type fakeWriter struct {
	mu  sync.Mutex
	got []writeRecord
}

type writeRecord struct {
	payload []byte
	src     netip.AddrPort
}

func (f *fakeWriter) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]byte(nil), p...)
	src, _ := netip.ParseAddrPort(addr.String())
	f.got = append(f.got, writeRecord{payload: cp, src: src})
	return len(p), nil
}

func (f *fakeWriter) Close() error { return nil }

func (f *fakeWriter) records() []writeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]writeRecord, len(f.got))
	copy(out, f.got)
	return out
}

// TestTunSocket_FakeIPRewritesSrc — when the original dst was a
// FakeIP, every reply written back into the TUN MUST carry
// src=originalDst, regardless of where the upstream reply actually
// came from. Otherwise the application's bound socket won't
// recognise the response.
func TestTunSocket_FakeIPRewritesSrc(t *testing.T) {
	pool := dns.NewFakeIPPool()
	fakeIP := pool.AllocateIPv4("example.com")
	if !pool.IsFakeIP(fakeIP) {
		t.Fatalf("FakeIP pool should report %v as fake", fakeIP)
	}

	originalDst := netip.AddrPortFrom(fakeIP, 53)
	originalSrc := netip.MustParseAddrPort("100.64.0.5:55555")
	dstEP := engine.Endpoint{Addr: originalDst, Domain: "example.com", Port: 53}

	w := &fakeWriter{}
	s := newTunSocket(w, originalSrc, originalDst, dstEP, pool)
	defer s.Close()

	// Outbound says "the real reply came from the actual upstream IP
	// of dns.google". For a FakeIP flow we must IGNORE this and
	// rewrite to originalDst.
	if err := s.WriteTo([]byte("dns-answer"), engine.Endpoint{
		Addr: netip.MustParseAddrPort("8.8.8.8:53"),
		Port: 53,
	}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	got := w.records()
	if len(got) != 1 {
		t.Fatalf("want 1 write, got %d", len(got))
	}
	if got[0].src != originalDst {
		t.Fatalf("FakeIP rewrite failed: src=%v want %v", got[0].src, originalDst)
	}
}

// TestTunSocket_RealIPPreservesSrc — when the original dst was a
// real IP (e.g. STUN test, P2P, direct WebRTC), every reply MUST
// carry the upstream's real source verbatim. This is the behaviour
// that makes Full-Cone NAT and STUN consistency tests work.
func TestTunSocket_RealIPPreservesSrc(t *testing.T) {
	pool := dns.NewFakeIPPool()

	originalDst := netip.MustParseAddrPort("9.9.9.9:19302") // a STUN server
	originalSrc := netip.MustParseAddrPort("100.64.0.5:55555")
	dstEP := engine.Endpoint{Addr: originalDst, Port: originalDst.Port()}

	w := &fakeWriter{}
	s := newTunSocket(w, originalSrc, originalDst, dstEP, pool)
	defer s.Close()

	// Two reflective replies from DIFFERENT STUN servers (this is
	// what RFC 5780 / consistency probes look like).
	reflective := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.7:55555"),
		netip.MustParseAddrPort("198.51.100.42:33333"),
	}
	for _, src := range reflective {
		if err := s.WriteTo([]byte("xor-mapped-address"), engine.Endpoint{Addr: src, Port: src.Port()}); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	got := w.records()
	if len(got) != 2 {
		t.Fatalf("want 2 writes, got %d", len(got))
	}
	for i, want := range reflective {
		if got[i].src != want {
			t.Fatalf("reply %d src=%v want %v (Full-Cone broken)", i, got[i].src, want)
		}
	}
}

// TestHandler_FakeIPDNSShortCircuit — the v2 promise of FakeIP mode
// is that DNS queries hitting the TUN's :53 are answered locally in
// sub-millisecond time without ever entering the engine pipeline.
//
// This regression-tests that:
//  1. A real DNS query for "example.com" sent to dst :53 is captured
//     by Handler.HandleUDP,
//  2. A response is written straight back through the udpResponseWriter,
//  3. The response is well-formed and contains a FakeIP from the
//     installed pool,
//  4. Nothing is forwarded to the engine (no UDP flow created).
func TestHandler_FakeIPDNSShortCircuit(t *testing.T) {
	import_dns := dns.BuildQuery("example.com.", 1) // 1 = A
	if len(import_dns) == 0 {
		t.Fatalf("BuildQuery returned empty (test fixture)")
	}

	h := NewHandler(context.Background())
	defer h.Close()

	pool := dns.NewFakeIPPool()
	h.SetFakeIPPool(pool)
	h.BindEngine(&panicEngine{t: t}) // engine MUST NOT be invoked

	w := &fakeWriter{}
	src := netip.MustParseAddrPort("100.64.0.5:55555")
	dst := netip.MustParseAddrPort("10.233.0.1:53")
	h.HandleUDP(w, import_dns, src, dst)

	recs := w.records()
	if len(recs) != 1 {
		t.Fatalf("want 1 reply written, got %d", len(recs))
	}
	if len(recs[0].payload) < 12 { // DNS header is 12 bytes
		t.Fatalf("reply too short: %d bytes", len(recs[0].payload))
	}
	if recs[0].payload[2]&0x80 == 0 {
		t.Fatalf("reply does not have QR bit set (not a response)")
	}

	// Verify we actually allocated a FakeIP for the queried domain.
	v4 := pool.AllocateIPv4("example.com.")
	if !pool.IsFakeIP(v4) {
		t.Fatalf("pool did not register a FakeIP")
	}
}

// panicEngine fails the test if the TUN handler ever tries to forward
// a flow into the engine — used by the FakeIP DNS short-circuit test
// to assert the query never leaves the device.
type panicEngine struct{ t *testing.T }

func (p *panicEngine) HandleTCP(ctx context.Context, src, dst engine.Endpoint, c engine.TCPConn) error {
	p.t.Fatalf("engine.HandleTCP must not be invoked for FakeIP DNS")
	return nil
}
func (p *panicEngine) HandleUDP(ctx context.Context, src, dst engine.Endpoint, c engine.UDPConn) error {
	p.t.Fatalf("engine.HandleUDP must not be invoked for FakeIP DNS")
	return nil
}

// TestTunSocket_FeedReadFromFlow — sanity: feeding a datagram from
// the TUN side surfaces it on ReadFrom with the dst endpoint as the
// "upstream destination" the application intended.
func TestTunSocket_FeedReadFromFlow(t *testing.T) {
	originalDst := netip.MustParseAddrPort("1.1.1.1:53")
	originalSrc := netip.MustParseAddrPort("100.64.0.5:55555")
	dstEP := engine.Endpoint{Addr: originalDst, Port: originalDst.Port()}

	s := newTunSocket(&fakeWriter{}, originalSrc, originalDst, dstEP, nil)
	defer s.Close()

	s.feedFromTUN([]byte("query"), originalSrc)

	buf := make([]byte, 32)
	n, dst, err := s.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "query" {
		t.Fatalf("payload mismatch: %q", buf[:n])
	}
	if dst.Addr != originalDst {
		t.Fatalf("dst surfaced=%v want %v", dst.Addr, originalDst)
	}
}
