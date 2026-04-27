// Package ewpclient is the Outbound that dials an EWP v2 tunnel.
//
// Each Outbound instance maps to one upstream EWP server (one
// transport.Transport). The Outbound owns ONE SecureStream per
// concrete client source-address (engine.Endpoint as src), so that:
//
//   - new TCP flows from the same src reuse the same encrypted tunnel
//   - new UDP sub-sessions from the same src multiplex into the same
//     SecureStream as independent GlobalIDs
//   - per-(src, real-remote) reply routing is preserved end-to-end
//     (the linchpin of Full-Cone NAT and STUN consistency)
//
// The Outbound is goroutine-safe.
package ewpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"ewp-core/engine"
	"ewp-core/log"
	v2 "ewp-core/protocol/ewp/v2"
	"ewp-core/transport"
)

// Outbound implements engine.Outbound by dialing EWP v2 tunnels via
// an underlying transport.Transport.
type Outbound struct {
	tag       string
	transport transport.Transport
	uuid      [v2.UUIDLen]byte

	mu      sync.Mutex
	tunnels map[engine.Endpoint]*tunnel // keyed by inbound src
	closed  bool
}

// New constructs a fresh ewpclient outbound.
//
// transport is any TunnelConn-producing transport (websocket, grpc,
// h3grpc, xhttp). uuid is the PSK identifying this client to the
// server.
func New(tag string, t transport.Transport, uuid [v2.UUIDLen]byte) *Outbound {
	if tag == "" {
		tag = "ewpclient"
	}
	return &Outbound{
		tag:       tag,
		transport: t,
		uuid:      uuid,
		tunnels:   make(map[engine.Endpoint]*tunnel),
	}
}

func (o *Outbound) Tag() string { return o.tag }

func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	for k, t := range o.tunnels {
		t.close()
		delete(o.tunnels, k)
	}
	return nil
}

// DialTCP opens a fresh TCP-mode SecureStream and returns it as a
// TCPConn. Each TCP flow gets its own SecureStream (TCP semantics
// don't multiplex inside one v2 stream).
func (o *Outbound) DialTCP(ctx context.Context, dst engine.Endpoint) (engine.TCPConn, error) {
	if o.isClosed() {
		return nil, errors.New("ewpclient: outbound closed")
	}
	addr, err := endpointToAddress(dst)
	if err != nil {
		return nil, err
	}
	ss, _, err := dialNew(o.transport, o.uuid, v2.CommandTCP, addr)
	if err != nil {
		return nil, fmt.Errorf("ewpclient: dial TCP %s: %w", dst, err)
	}
	c := &tcpConn{ss: ss, readBuf: make([]byte, 0)}
	return c, nil
}

// DialUDP opens (or reuses) a UDP-mode SecureStream keyed by the
// inbound source address (taken from ctx via WithUDPSource), and
// allocates a fresh GlobalID for this destination.
//
// If no source is supplied, a fresh per-call SecureStream is created
// (degraded mode; per-src multiplexing won't work and STUN
// consistency will appear correct only by accident).
func (o *Outbound) DialUDP(ctx context.Context, dst engine.Endpoint) (engine.UDPConn, error) {
	if o.isClosed() {
		return nil, errors.New("ewpclient: outbound closed")
	}
	addr, err := endpointToAddress(dst)
	if err != nil {
		return nil, err
	}

	src, _ := UDPSourceFromContext(ctx)
	tun, err := o.tunnelForSrc(ctx, src, addr)
	if err != nil {
		return nil, err
	}
	gid := v2.NewGlobalID()
	sub := tun.openSub(gid, addr)
	return sub, nil
}

// tunnelForSrc returns (or creates) the per-src SecureStream tunnel.
//
// initialAddr is used only as the first UDP_NEW target, in case this
// is a brand-new tunnel that needs to send its handshake right away.
// Subsequent sub-sessions on the same tunnel use their own targets.
func (o *Outbound) tunnelForSrc(ctx context.Context, src engine.Endpoint, initialAddr v2.Address) (*tunnel, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if t, ok := o.tunnels[src]; ok && t.alive() {
		return t, nil
	}

	ss, _, err := dialNew(o.transport, o.uuid, v2.CommandUDP, initialAddr)
	if err != nil {
		return nil, fmt.Errorf("ewpclient: dial UDP tunnel: %w", err)
	}
	t := newTunnel(ss, func() { o.dropTunnel(src) })
	o.tunnels[src] = t
	go t.recvLoop()
	return t, nil
}

func (o *Outbound) dropTunnel(src engine.Endpoint) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if t, ok := o.tunnels[src]; ok {
		t.close()
		delete(o.tunnels, src)
	}
}

func (o *Outbound) isClosed() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed
}

// ----------------------------------------------------------------------
// dialNew: transport.Dial + EWP v2 handshake
// ----------------------------------------------------------------------

func dialNew(tr transport.Transport, uuid [v2.UUIDLen]byte, cmd v2.Command, initial v2.Address) (*v2.SecureStream, *v2.HandshakeResult, error) {
	tc, err := tr.Dial()
	if err != nil {
		return nil, nil, fmt.Errorf("transport dial: %w", err)
	}
	// SecureStream happens AFTER the v2 handshake. We perform the
	// handshake using the raw transport and then wrap it.
	state, err := v2.WriteClientHello(tc.SendMessage, uuid, cmd, initial)
	if err != nil {
		_ = tc.Close()
		return nil, nil, fmt.Errorf("WriteClientHello: %w", err)
	}
	shBytes, err := tc.ReadMessage()
	if err != nil {
		_ = tc.Close()
		return nil, nil, fmt.Errorf("read ServerHello: %w", err)
	}
	res, err := state.ReadServerHello(shBytes)
	if err != nil {
		_ = tc.Close()
		return nil, nil, fmt.Errorf("ReadServerHello: %w", err)
	}
	ss, err := v2.NewClientSecureStream(tc, res.Keys)
	if err != nil {
		_ = tc.Close()
		return nil, nil, fmt.Errorf("NewClientSecureStream: %w", err)
	}
	return ss, res, nil
}

// ----------------------------------------------------------------------
// tcpConn — TCP-mode SecureStream wrapped as engine.TCPConn
// ----------------------------------------------------------------------

type tcpConn struct {
	ss *v2.SecureStream

	readMu  sync.Mutex
	readBuf []byte // any leftover bytes from the previous Recv
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		ev, err := c.ss.Recv()
		if err != nil {
			return 0, err
		}
		switch ev.Type {
		case v2.FrameTCPData:
			n := copy(p, ev.Payload)
			if n < len(ev.Payload) {
				c.readBuf = append(c.readBuf[:0], ev.Payload[n:]...)
			}
			return n, nil
		case v2.FramePing:
			_ = c.ss.SendPong(ev.Payload)
		case v2.FramePong, v2.FramePaddingOnly:
			// ignore
		default:
			// any other frame on a TCP-mode SecureStream is a
			// protocol error.
			return 0, fmt.Errorf("ewpclient: unexpected frame type %d on TCP stream", ev.Type)
		}
	}
}

func (c *tcpConn) Write(p []byte) (int, error) {
	if err := c.ss.SendTCPData(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *tcpConn) Close() error { return c.ss.Close() }

// Compile-time check: io.ReadWriteCloser fits engine.TCPConn.
var _ io.ReadWriteCloser = (*tcpConn)(nil)
var _ engine.TCPConn = (*tcpConn)(nil)

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func endpointToAddress(e engine.Endpoint) (v2.Address, error) {
	if e.IsDomain() {
		port := e.Port
		if port == 0 {
			port = e.Addr.Port()
		}
		if port == 0 {
			return v2.Address{}, errors.New("ewpclient: zero port for domain endpoint")
		}
		return v2.Address{Domain: e.Domain, Port: port}, nil
	}
	if !e.Addr.IsValid() {
		return v2.Address{}, errors.New("ewpclient: endpoint has neither domain nor valid addr")
	}
	return v2.Address{Addr: e.Addr}, nil
}

func addressToEndpoint(a v2.Address) engine.Endpoint {
	if a.IsDomain() {
		return engine.Endpoint{Domain: a.Domain, Port: a.Port}
	}
	return engine.Endpoint{Addr: a.Addr, Port: a.Addr.Port()}
}

// ----------------------------------------------------------------------
// UDP source plumbing
// ----------------------------------------------------------------------

type ctxKeyUDPSrc struct{}

// WithUDPSource annotates ctx with the inbound UDP source address.
// Inbounds (notably tun) MUST call this before invoking
// engine.HandleUDP so that ewpclient can multiplex per-src.
func WithUDPSource(parent context.Context, src engine.Endpoint) context.Context {
	return context.WithValue(parent, ctxKeyUDPSrc{}, src)
}

// UDPSourceFromContext retrieves the source previously installed by
// WithUDPSource. The bool indicates presence.
func UDPSourceFromContext(ctx context.Context) (engine.Endpoint, bool) {
	v, ok := ctx.Value(ctxKeyUDPSrc{}).(engine.Endpoint)
	return v, ok
}

// log helper – prevents unused import on logger-less builds.
var _ = log.V
