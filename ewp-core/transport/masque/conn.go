package masque

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	masqueauth "ewp-core/protocol/masque"
	"ewp-core/transport"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const capsuleProtocolHeaderValue = "?1"

// contextIDZero is the context-id=0 prefix required by RFC 9298 §4.
// QUIC variable-length integer encoding of 0 is exactly 0x00 (one byte).
var contextIDZero = []byte{0x00}

// udpWritePool reuses send-side datagram buffers to eliminate per-packet
// heap allocations on the UDP hot path.
//
// Capacity is pre-sized for context-id(1) + typical UDP payload (≤1500 bytes).
// SendDatagram is synchronous: QUIC copies the bytes before returning, so it is
// safe to put the buffer back immediately after the call returns.
var udpWritePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 1+1500)
		return &b
	},
}

// Conn implements transport.TunnelConn over HTTP/3.
//
// TCP mode  (after Connect):     request stream used as a bidirectional byte pipe.
// UDP mode  (after ConnectUDP):  QUIC datagrams sent/received via the request stream
//                                 per RFC 9298 (context-id=0 prefix).
type Conn struct {
	clientConn *http3.ClientConn
	// connCtx is the QUIC connection's context; cancelled when the connection is lost.
	// Used as the context for ReceiveDatagram so that goroutines blocked on datagram
	// reads are unblocked when the connection dies (H-2: prevents goroutine leaks).
	connCtx    context.Context
	uuid       [16]byte
	template   *uritemplate.Template

	tcpStream *http3.RequestStream
	udpStream *http3.RequestStream
	udpTarget netip.AddrPort
}

func newConn(cc *http3.ClientConn, uuid [16]byte, tmpl *uritemplate.Template) *Conn {
	return &Conn{clientConn: cc, connCtx: cc.Context(), uuid: uuid, template: tmpl}
}

// ── TCP ──────────────────────────────────────────────────────────────────────

// Connect establishes a TCP tunnel via HTTP/3 CONNECT.
// The server dials `target` (host:port) and bridges the stream bidirectionally.
func (c *Conn) Connect(target string, initialData []byte) error {
	authHdr, err := masqueauth.GenerateAuthHeader(c.uuid)
	if err != nil {
		return fmt.Errorf("masque: generate auth: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		Host:   target,
		Header: authHdr,
		URL:    &url.URL{Host: target},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return fmt.Errorf("masque: open request stream: %w", err)
	}

	if err := rstr.SendRequestHeader(req); err != nil {
		return fmt.Errorf("masque: send CONNECT header: %w", err)
	}

	rsp, err := rstr.ReadResponse()
	if err != nil {
		return fmt.Errorf("masque: read CONNECT response: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return fmt.Errorf("masque: CONNECT rejected: %d", rsp.StatusCode)
	}

	c.tcpStream = rstr

	if len(initialData) > 0 {
		if _, err := rstr.Write(initialData); err != nil {
			return fmt.Errorf("masque: write initial data: %w", err)
		}
	}
	return nil
}

// Read reads from the TCP tunnel stream.
func (c *Conn) Read(buf []byte) (int, error) {
	return c.tcpStream.Read(buf)
}

// Write writes to the TCP tunnel stream.
func (c *Conn) Write(data []byte) error {
	_, err := c.tcpStream.Write(data)
	return err
}

// ── UDP ──────────────────────────────────────────────────────────────────────

// ConnectUDP establishes a UDP tunnel via HTTP/3 Extended CONNECT (connect-udp).
// Each ConnectUDP call opens a dedicated request stream; QUIC datagrams on that
// stream carry raw UDP payloads with a single-byte context-id=0 prefix (RFC 9298).
func (c *Conn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	host := ""
	port := target.Port

	if target.Domain != "" {
		host = target.Domain
	} else {
		host = escapeHost(target.Addr.Addr().String())
		if target.Addr.IsValid() {
			port = target.Addr.Port()
		}
	}

	expanded, err := c.template.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(strconv.Itoa(int(port))),
	})
	if err != nil {
		return fmt.Errorf("masque: expand URI template: %w", err)
	}

	u, err := url.Parse(expanded)
	if err != nil {
		return fmt.Errorf("masque: parse expanded URL: %w", err)
	}

	authHdr, err := masqueauth.GenerateAuthHeader(c.uuid)
	if err != nil {
		return fmt.Errorf("masque: generate auth: %w", err)
	}
	authHdr.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)

	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		Host:   u.Host,
		URL:    u,
		Header: authHdr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return fmt.Errorf("masque: open UDP request stream: %w", err)
	}

	if err := rstr.SendRequestHeader(req); err != nil {
		rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		return fmt.Errorf("masque: send CONNECT-UDP header: %w", err)
	}

	rsp, err := rstr.ReadResponse()
	if err != nil {
		rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		return fmt.Errorf("masque: read CONNECT-UDP response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		return fmt.Errorf("masque: CONNECT-UDP rejected: %d", rsp.StatusCode)
	}

	c.udpStream = rstr
	if target.Addr.IsValid() {
		c.udpTarget = target.Addr
	}

	if len(initialData) > 0 {
		if err := c.WriteUDP(target, initialData); err != nil {
			return fmt.Errorf("masque: write initial UDP: %w", err)
		}
	}
	return nil
}

// WriteUDP sends a UDP datagram through the tunnel.
// The endpoint target is ignored on subsequent calls; the proxy uses the
// target established in ConnectUDP.
//
// Hot-path: the write buffer is taken from udpWritePool and returned after
// SendDatagram returns (QUIC copies the payload before returning).
func (c *Conn) WriteUDP(_ transport.Endpoint, data []byte) error {
	bufp := udpWritePool.Get().(*[]byte)
	buf := append((*bufp)[:0], contextIDZero...)
	buf = append(buf, data...)
	err := c.udpStream.SendDatagram(buf)
	*bufp = buf
	udpWritePool.Put(bufp)
	return err
}

// ReadUDP receives one UDP datagram and returns its payload.
//
// The returned slice is a sub-slice of the buffer allocated by ReceiveDatagram;
// ownership transfers to the caller — no extra copy is made.
// Blocks until a datagram arrives or the underlying QUIC connection is closed.
func (c *Conn) ReadUDP() ([]byte, error) {
	data, err := c.udpStream.ReceiveDatagram(c.connCtx)
	if err != nil {
		return nil, err
	}
	return stripContextID(data)
}

// ReadUDPTo reads a UDP datagram payload into buf (zero-copy path).
// Blocks until a datagram arrives or the underlying QUIC connection is closed.
func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	data, err := c.udpStream.ReceiveDatagram(c.connCtx)
	if err != nil {
		return 0, err
	}
	payload, err := stripContextID(data)
	if err != nil {
		return 0, err
	}
	return copy(buf, payload), nil
}

// ReadUDPFrom reads a UDP datagram and returns its payload plus the source address.
// The source address is always the target endpoint established in ConnectUDP.
func (c *Conn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	n, err := c.ReadUDPTo(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, c.udpTarget, nil
}

// ── Common ───────────────────────────────────────────────────────────────────

// Close closes whichever stream is open.
func (c *Conn) Close() error {
	var errs []error
	if c.tcpStream != nil {
		c.tcpStream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		if err := c.tcpStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.udpStream != nil {
		c.udpStream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		if err := c.udpStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// StartPing is a no-op; QUIC KeepAlivePeriod handles liveness.
func (c *Conn) StartPing(_ time.Duration) chan struct{} {
	return nil
}

// stripContextID strips the RFC 9298 context-id=0 prefix from a raw QUIC datagram.
//
// Fast-path contract: QUIC variable-length integer encoding of 0 is exactly the
// single byte 0x00 (two-bit prefix 00, six-bit value 000000). We exploit this
// instead of calling quicvarint.Parse, eliminating an allocation and two
// branches per datagram on the UDP receive hot path.
//
// Returns an error if data is empty or if the first byte is not 0x00 (i.e., an
// unsupported context-id is present — RFC 9298 §4 requires clients to ignore
// datagrams with unknown context-ids, but we surface it as an error so the
// caller can log and skip rather than silently misbehave).
func stripContextID(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("masque: empty datagram")
	}
	if data[0] != 0x00 {
		return nil, fmt.Errorf("masque: unsupported context-id 0x%02x", data[0])
	}
	return data[1:], nil
}

// escapeHost percent-encodes colons in IPv6 addresses per RFC 6570.
func escapeHost(s string) string {
	if net.ParseIP(s) != nil && len(s) > 0 && s[0] != '[' {
		// pure IPv6 address without brackets — must escape colons for URI template
		out := make([]byte, 0, len(s)+8)
		for i := 0; i < len(s); i++ {
			if s[i] == ':' {
				out = append(out, '%', '3', 'A')
			} else {
				out = append(out, s[i])
			}
		}
		return string(out)
	}
	return s
}

// Ensure Conn satisfies the interface at compile time.
var _ transport.TunnelConn = (*Conn)(nil)
var _ io.ReadCloser = (*Conn)(nil)
