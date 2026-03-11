package webtransport

import (
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"ewp-core/protocol/ewp"
	"ewp-core/transport"

	wtransport "github.com/quic-go/webtransport-go"
)

// Conn implements transport.TunnelConn over a single WebTransport bidi stream.
// Each Dial() opens one stream; TCP and UDP both use the raw byte stream with EWP framing.
type Conn struct {
	stream      *wtransport.Stream
	uuid        [16]byte
	udpGlobalID [8]byte
	mu          sync.Mutex
	leftover    []byte
}

func newConn(stream *wtransport.Stream, uuid [16]byte) *Conn {
	return &Conn{
		stream: stream,
		uuid:   uuid,
	}
}

// Connect sends an EWP TCP handshake and waits for the 26-byte response.
func (c *Conn) Connect(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if _, err := c.stream.Write(handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	var respBuf [26]byte
	if _, err := io.ReadFull(c.stream, respBuf[:]); err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respBuf[:], req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}
	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if len(initialData) > 0 {
		if _, err := c.stream.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}
	return nil
}

// ConnectUDP sends an EWP UDP handshake then the initial UDPStatusNew packet.
// Domain targets are sent to the server without client-side DNS resolution;
// the server resolves the domain from the EWP handshake.
func (c *Conn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode EWP UDP handshake: %w", err)
	}

	if _, err := c.stream.Write(handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	var respBuf [26]byte
	if _, err := io.ReadFull(c.stream, respBuf[:]); err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respBuf[:], req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}
	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	c.udpGlobalID = ewp.NewGlobalID()

	// Use target.Addr directly; when only a domain is available (TUN+FakeIP mode),
	// target.Addr is zero and the server falls back to the handshake target.
	targetAddr := target.Addr

	// Use zero-alloc AppendUDPAddrFrame instead of EncodeUDPAddrPacket.
	bufp := ewp.UDPWriteBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusNew, targetAddr, initialData)

	_, err = c.stream.Write(buf)
	*bufp = buf
	ewp.UDPWriteBufPool.Put(bufp)
	if err != nil {
		return fmt.Errorf("send UDPStatusNew: %w", err)
	}
	return nil
}

// WriteUDP sends an EWP UDP Keep frame over the stream.
// Uses sync.Pool to avoid per-packet heap allocation on the hot path.
func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
	// Use target.Addr directly; zero value means the server uses initTarget.
	targetAddr := target.Addr

	bufp := ewp.UDPWriteBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, targetAddr, data)

	c.mu.Lock()
	_, err := c.stream.Write(buf)
	c.mu.Unlock()

	*bufp = buf
	ewp.UDPWriteBufPool.Put(bufp)
	return err
}

// ReadUDPFrom reads an EWP UDP frame directly from the stream and returns
// the payload length and remote address (zero-allocation via pool buffer).
func (c *Conn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	return ewp.DecodeUDPAddrPacketTo(c.stream, buf)
}

// ReadUDP reads an EWP UDP frame and returns the payload.
func (c *Conn) ReadUDP() ([]byte, error) {
	pkt, err := ewp.DecodeUDPPacket(c.stream)
	if err != nil {
		return nil, err
	}
	return pkt.Payload, nil
}

// ReadUDPTo reads an EWP UDP frame payload into buf.
func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	pkt, err := ewp.DecodeUDPPacket(c.stream)
	if err != nil {
		return 0, err
	}
	return copy(buf, pkt.Payload), nil
}

// Read reads raw bytes from the stream (for TCP relay).
func (c *Conn) Read(buf []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(buf, c.leftover)
		c.leftover = c.leftover[n:]
		if len(c.leftover) == 0 {
			c.leftover = nil
		}
		return n, nil
	}
	return c.stream.Read(buf)
}

// Write writes raw bytes to the stream (for TCP relay).
func (c *Conn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.stream.Write(data)
	return err
}

// Close closes the WebTransport stream.
func (c *Conn) Close() error {
	return c.stream.Close()
}

// StartPing returns nil; QUIC keepalives handle liveness.
// Callers must check for nil before closing the returned channel.
func (c *Conn) StartPing(_ time.Duration) chan struct{} {
	return nil
}
