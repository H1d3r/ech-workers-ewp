package ewpclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"ewp-core/engine"
	v2 "ewp-core/protocol/ewp/v2"
	"ewp-core/transport"
)

// ----------------------------------------------------------------------
// In-memory transport pair, mirrors v2/v2_test.go's memTransport but
// here we expose it as transport.Transport (Dial returns a TunnelConn)
// rather than the raw type.
// ----------------------------------------------------------------------

type memTransport struct {
	in  chan []byte
	out chan []byte

	mu     sync.Mutex
	closed bool
}

func newMemPair() (*memTransport, *memTransport) {
	a2b := make(chan []byte, 64)
	b2a := make(chan []byte, 64)
	return &memTransport{in: b2a, out: a2b}, &memTransport{in: a2b, out: b2a}
}

func (m *memTransport) SendMessage(b []byte) error {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return errors.New("memTransport closed")
	}
	cp := append([]byte(nil), b...)
	select {
	case m.out <- cp:
		return nil
	case <-time.After(time.Second):
		return errors.New("memTransport send timeout")
	}
}

func (m *memTransport) ReadMessage() ([]byte, error) {
	b, ok := <-m.in
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}

func (m *memTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.out)
	return nil
}

// memDialer is a transport.Transport whose Dial returns a freshly
// paired memTransport. The other side of the pair is delivered on the
// `incoming` channel for the test fixture's "server" to pick up.
type memDialer struct {
	incoming chan transport.TunnelConn
}

func (d *memDialer) Dial() (transport.TunnelConn, error) {
	cli, srv := newMemPair()
	d.incoming <- srv
	return cli, nil
}

func (d *memDialer) Name() string                                 { return "mem" }
func (d *memDialer) SetBypassConfig(_ *transport.BypassConfig)    {}

// ----------------------------------------------------------------------
// TestEnd2End_TCPRoundTrip
//
// Setup:
//   - one Outbound (ewpclient) wired to memDialer
//   - one fake "server": for each incoming TunnelConn, run the v2
//     server-side handshake, build a SecureStream, and echo all
//     TCP_DATA frames back
//   - test calls Outbound.DialTCP, writes "ping", reads "PING-back"
// ----------------------------------------------------------------------
func TestEnd2End_TCPRoundTrip(t *testing.T) {
	uuid := [v2.UUIDLen]byte{0xaa}
	dialer := &memDialer{incoming: make(chan transport.TunnelConn, 4)}
	ob := New("ewp-test", dialer, uuid)
	defer ob.Close()

	// Spawn the fake server.
	go runEchoServer(t, dialer.incoming, []byte("PING-back"), uuid)

	conn, err := ob.DialTCP(context.Background(), engine.Endpoint{
		Addr: netip.MustParseAddrPort("1.2.3.4:443"),
		Port: 443,
	})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("PING-back")) {
		t.Fatalf("got %q want PING-back", buf[:n])
	}
}

// ----------------------------------------------------------------------
// TestEnd2End_UDPRealRemote
//
// The bug we are guarding against: the v1 "ReadUDPFrom dropped the
// real remote with a `_`" issue. The v2 stack must surface the
// server-reported real remote on every datagram.
//
// Setup:
//   - Outbound DialUDP to dst1
//   - Server handshake, then send TWO inbound UDP_DATA frames whose
//     META address differs (simulating two STUN servers responding to
//     a consistency probe)
//   - The test's ReadFrom calls MUST observe both distinct sources
// ----------------------------------------------------------------------
func TestEnd2End_UDPRealRemote(t *testing.T) {
	uuid := [v2.UUIDLen]byte{0xbb}
	dialer := &memDialer{incoming: make(chan transport.TunnelConn, 4)}
	ob := New("ewp-test", dialer, uuid)
	defer ob.Close()

	// Run a server that, after handshake, immediately sends two
	// reflective replies with distinct source addresses, then idles.
	dst1 := netip.MustParseAddrPort("9.9.9.9:19302")
	reflected := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.7:55555"),
		netip.MustParseAddrPort("198.51.100.42:33333"),
	}
	go runReflectiveServer(t, dialer.incoming, uuid, reflected)

	ctx := WithUDPSource(context.Background(), engine.Endpoint{
		Addr: netip.MustParseAddrPort("100.64.0.5:5555"),
		Port: 5555,
	})
	udpConn, err := ob.DialUDP(ctx, engine.Endpoint{Addr: dst1, Port: dst1.Port()})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer udpConn.Close()

	// We MUST send a payload first so the wire emits UDP_NEW; that
	// gives the server side something to react to.
	if err := udpConn.WriteTo([]byte("stun-bind"), engine.Endpoint{Addr: dst1, Port: dst1.Port()}); err != nil {
		t.Fatalf("first WriteTo: %v", err)
	}

	gotSources := map[netip.AddrPort]bool{}
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 1500)
	for len(gotSources) < 2 && time.Now().Before(deadline) {
		n, src, err := udpConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		_ = n
		gotSources[src.Addr] = true
	}

	for _, want := range reflected {
		if !gotSources[want] {
			t.Fatalf("reply with src=%v never arrived. seen=%v", want, gotSources)
		}
	}
}

// ----------------------------------------------------------------------
// runEchoServer accepts ONE TunnelConn from incoming, performs the
// server-side v2 handshake under the supplied uuid, and echoes every
// TCP_DATA frame back as `reply`.
// ----------------------------------------------------------------------
func runEchoServer(t *testing.T, incoming <-chan transport.TunnelConn, reply []byte, uuid [v2.UUIDLen]byte) {
	t.Helper()
	tc := <-incoming
	hi, err := tc.ReadMessage()
	if err != nil {
		t.Errorf("server ReadMessage(CH): %v", err)
		return
	}
	helloOut, res, err := v2.AcceptClientHello(hi, v2.MakeUUIDLookup([][v2.UUIDLen]byte{uuid}))
	if err != nil {
		t.Errorf("AcceptClientHello: %v", err)
		return
	}
	if err := tc.SendMessage(helloOut); err != nil {
		t.Errorf("server send SH: %v", err)
		return
	}
	ss, err := v2.NewServerSecureStream(tc, res.Keys)
	if err != nil {
		t.Errorf("NewServerSecureStream: %v", err)
		return
	}
	defer ss.Close()
	for {
		ev, err := ss.Recv()
		if err != nil {
			return
		}
		if ev.Type == v2.FrameTCPData {
			if err := ss.SendTCPData(reply); err != nil {
				return
			}
		}
	}
}

// ----------------------------------------------------------------------
// runReflectiveServer accepts ONE UDP-mode TunnelConn, awaits the
// client's first UDP_NEW, then emits ONE UDP_DATA frame per addr in
// `srcs` echoing back synthetic payloads with each addr placed in
// the frame meta as the "real remote".
// ----------------------------------------------------------------------
func runReflectiveServer(t *testing.T, incoming <-chan transport.TunnelConn, uuid [v2.UUIDLen]byte, srcs []netip.AddrPort) {
	t.Helper()
	tc := <-incoming
	hi, err := tc.ReadMessage()
	if err != nil {
		t.Errorf("server ReadMessage(CH): %v", err)
		return
	}
	helloOut, res, err := v2.AcceptClientHello(hi, v2.MakeUUIDLookup([][v2.UUIDLen]byte{uuid}))
	if err != nil {
		t.Errorf("AcceptClientHello: %v", err)
		return
	}
	if err := tc.SendMessage(helloOut); err != nil {
		t.Errorf("server send SH: %v", err)
		return
	}
	ss, err := v2.NewServerSecureStream(tc, res.Keys)
	if err != nil {
		t.Errorf("NewServerSecureStream: %v", err)
		return
	}
	defer ss.Close()

	ev, err := ss.Recv()
	if err != nil {
		t.Errorf("recv UDP_NEW: %v", err)
		return
	}
	if ev.Type != v2.FrameUDPNew {
		t.Errorf("expected UDP_NEW, got %d", ev.Type)
		return
	}
	gid := ev.GlobalID
	for i, s := range srcs {
		payload := []byte{byte('A' + i)}
		if err := ss.SendUDPData(gid, v2.Address{Addr: s}, payload); err != nil {
			t.Errorf("send UDP_DATA: %v", err)
			return
		}
	}
	// Idle until client closes.
	for {
		if _, err := ss.Recv(); err != nil {
			return
		}
	}
}
