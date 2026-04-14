package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ewp-core/transport"
)

// MockTunnelConn simulates a proxy tunnel connection
type MockTunnelConn struct {
	readChan chan *mockUDPResponse
	closed   atomic.Bool
}

type mockUDPResponse struct {
	data       []byte
	remoteAddr netip.AddrPort
}

func (m *MockTunnelConn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	if m.closed.Load() {
		return 0, netip.AddrPort{}, context.Canceled
	}
	select {
	case resp := <-m.readChan:
		copy(buf, resp.data)
		return len(resp.data), resp.remoteAddr, nil
	case <-time.After(5 * time.Second):
		return 0, netip.AddrPort{}, context.DeadlineExceeded
	}
}
func (m *MockTunnelConn) WriteUDP(endpoint transport.Endpoint, payload []byte) error { return nil }
func (m *MockTunnelConn) ConnectUDP(endpoint transport.Endpoint, initialData []byte) error {
	return nil
}
func (m *MockTunnelConn) Connect(target string, initialData []byte) error { return nil }
func (m *MockTunnelConn) ReadUDP() ([]byte, error)                        { return nil, nil }
func (m *MockTunnelConn) ReadUDPTo(buf []byte) (int, error)               { return 0, nil }
func (m *MockTunnelConn) Read(buf []byte) (int, error)                    { return 0, nil }
func (m *MockTunnelConn) Write(data []byte) error                         { return nil }
func (m *MockTunnelConn) StartPing(interval time.Duration) chan struct{} {
	return make(chan struct{})
}
func (m *MockTunnelConn) Close() error {
	m.closed.Store(true)
	return nil
}

// mockGVisorConn implements udpResponseWriter and captures written payloads.
type mockGVisorConn struct {
	mu      sync.Mutex
	written [][]byte
	closed  bool
}

func (c *mockGVisorConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	c.written = append(c.written, cp)
	return len(b), nil
}

func (c *mockGVisorConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *mockGVisorConn) Written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

// MockTransport for creating mock tunnel connections
type MockTransport struct {
	dialChan chan *MockTunnelConn
}

func (m *MockTransport) Dial() (transport.TunnelConn, error) { return <-m.dialChan, nil }
func (m *MockTransport) Name() string                        { return "mock" }
func (m *MockTransport) SetBypassConfig(cfg *transport.BypassConfig) {}

// ════════════════════════════════════════════════════════════════════════════════
// Test: Session is created for (src, dst) key
// ════════════════════════════════════════════════════════════════════════════════

func TestHandleUDP_SessionCreated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockTunnel := &MockTunnelConn{readChan: make(chan *mockUDPResponse, 1)}
	mockTransport := &MockTransport{dialChan: make(chan *MockTunnelConn, 1)}
	mockTransport.dialChan <- mockTunnel

	handler := NewHandler(ctx, mockTransport)

	clientSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 12345)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)
	conn := &mockGVisorConn{}

	handler.HandleUDP(conn, []byte("query"), clientSrc, dst)
	time.Sleep(50 * time.Millisecond)

	key := udpSessionKey{src: clientSrc, dst: dst}
	if _, ok := handler.udpSessions.Load(key); !ok {
		t.Fatal("expected session to be created for (src, dst) key")
	}
	t.Log("✓ session created")
}

// ════════════════════════════════════════════════════════════════════════════════
// Test: Response from tunnel is written back to gVisor conn
// ════════════════════════════════════════════════════════════════════════════════

func TestHandleUDP_ResponseWrittenToConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockTunnel := &MockTunnelConn{readChan: make(chan *mockUDPResponse, 1)}
	mockTransport := &MockTransport{dialChan: make(chan *MockTunnelConn, 1)}
	mockTransport.dialChan <- mockTunnel

	handler := NewHandler(ctx, mockTransport)

	clientSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 12345)
	dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)
	conn := &mockGVisorConn{}

	handler.HandleUDP(conn, []byte("query"), clientSrc, dst)
	time.Sleep(50 * time.Millisecond)

	response := []byte("response data")
	mockTunnel.readChan <- &mockUDPResponse{data: response, remoteAddr: dst}
	time.Sleep(200 * time.Millisecond)

	written := conn.Written()
	if len(written) != 1 {
		t.Fatalf("expected 1 response written to conn, got %d", len(written))
	}
	if string(written[0]) != string(response) {
		t.Errorf("response mismatch: got %q, want %q", written[0], response)
	}
	t.Log("✓ response written directly to gVisor conn")
}

// ════════════════════════════════════════════════════════════════════════════════
// Test: Same src, different dst → separate sessions, responses routed correctly
// ════════════════════════════════════════════════════════════════════════════════

func TestHandleUDP_SeparateSessionsPerDst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tunnel1 := &MockTunnelConn{readChan: make(chan *mockUDPResponse, 1)}
	tunnel2 := &MockTunnelConn{readChan: make(chan *mockUDPResponse, 1)}
	mockTransport := &MockTransport{dialChan: make(chan *MockTunnelConn, 2)}
	mockTransport.dialChan <- tunnel1
	mockTransport.dialChan <- tunnel2

	handler := NewHandler(ctx, mockTransport)

	clientSrc := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 1, 100}), 12345)
	dst1 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53)
	dst2 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 53)

	conn1 := &mockGVisorConn{}
	conn2 := &mockGVisorConn{}

	handler.HandleUDP(conn1, []byte("query1"), clientSrc, dst1)
	handler.HandleUDP(conn2, []byte("query2"), clientSrc, dst2)
	time.Sleep(100 * time.Millisecond)

	key1 := udpSessionKey{src: clientSrc, dst: dst1}
	key2 := udpSessionKey{src: clientSrc, dst: dst2}
	if _, ok := handler.udpSessions.Load(key1); !ok {
		t.Error("expected session for dst1")
	}
	if _, ok := handler.udpSessions.Load(key2); !ok {
		t.Error("expected session for dst2")
	}

	resp1 := []byte("response from 8.8.8.8")
	resp2 := []byte("response from 1.1.1.1")
	tunnel1.readChan <- &mockUDPResponse{data: resp1, remoteAddr: dst1}
	tunnel2.readChan <- &mockUDPResponse{data: resp2, remoteAddr: dst2}
	time.Sleep(200 * time.Millisecond)

	if w := conn1.Written(); len(w) != 1 || string(w[0]) != string(resp1) {
		t.Errorf("conn1: expected %q, got %v", resp1, w)
	}
	if w := conn2.Written(); len(w) != 1 || string(w[0]) != string(resp2) {
		t.Errorf("conn2: expected %q, got %v", resp2, w)
	}
	t.Log("✓ separate sessions per (src, dst) — responses routed to correct conns")
}

func contains(addrs []netip.AddrPort, target netip.AddrPort) bool {
	for _, a := range addrs {
		if a == target {
			return true
		}
	}
	return false
}
