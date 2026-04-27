package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"ewp-core/engine"
	"ewp-core/log"
)

// socks5UDPRelay multiplexes the single UDP socket bound by
// UDP_ASSOCIATE into per-(client_src, dst) engine.UDPConn flows.
//
// Each unique (atyp, addr, port) destination seen on an inbound
// SOCKS5 UDP packet creates a new engine.HandleUDP flow. Replies
// from upstream are wrapped back into SOCKS5 UDP headers using the
// real-remote address the outbound observed (that's the linchpin of
// Full-Cone NAT correctness, end-to-end).
type socks5UDPRelay struct {
	udpConn *net.UDPConn

	mu     sync.Mutex
	flows  map[flowKey]*udpFlow
	client netip.AddrPort // expected client UDP src; learned on first packet
	closed atomic.Bool
}

type flowKey struct {
	src netip.AddrPort // client's UDP src
	dst engine.Endpoint
}

func newSocks5UDPRelay(udpConn *net.UDPConn) *socks5UDPRelay {
	return &socks5UDPRelay{
		udpConn: udpConn,
		flows:   make(map[flowKey]*udpFlow),
	}
}

// run reads SOCKS5 UDP packets in a loop until close.
func (r *socks5UDPRelay) run(ctx context.Context, h engine.InboundHandler) {
	buf := make([]byte, 64*1024)
	for {
		_ = r.udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, src, err := r.udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.V("[socks5] UDP read: %v", err)
			return
		}

		if r.client == (netip.AddrPort{}) {
			r.client = src
		} else if src.Addr() != r.client.Addr() {
			// Source validation: drop packets from anyone other
			// than the client that opened the association.
			continue
		}

		if err := r.handlePacket(ctx, h, buf[:n], src); err != nil {
			log.V("[socks5] handle UDP: %v", err)
		}
	}
}

func (r *socks5UDPRelay) handlePacket(ctx context.Context, h engine.InboundHandler, pkt []byte, src netip.AddrPort) error {
	if len(pkt) < 10 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		return errors.New("invalid SOCKS5 UDP header")
	}
	atyp := pkt[3]
	dst, headerLen, err := parseSocksUDPAddr(pkt[3:], atyp)
	if err != nil {
		return err
	}
	headerLen++ // include the atyp byte itself
	payload := pkt[3+headerLen:]

	key := flowKey{src: src, dst: dst}

	r.mu.Lock()
	flow, exists := r.flows[key]
	if !exists {
		flow = newUDPFlow(r, src, dst)
		r.flows[key] = flow
		r.mu.Unlock()

		// Hand the brand-new flow to the engine.
		go func() {
			srcEP := engine.Endpoint{Addr: src, Port: src.Port()}
			if err := h.HandleUDP(ctx, srcEP, dst, flow); err != nil {
				log.V("[socks5] HandleUDP: %v", err)
				flow.close()
				r.removeFlow(key)
			}
		}()
	} else {
		r.mu.Unlock()
	}
	flow.feedFromClient(payload)
	return nil
}

func (r *socks5UDPRelay) removeFlow(k flowKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.flows, k)
}

func (r *socks5UDPRelay) close() {
	if r.closed.Swap(true) {
		return
	}
	r.mu.Lock()
	for k, f := range r.flows {
		f.close()
		delete(r.flows, k)
	}
	r.mu.Unlock()
	_ = r.udpConn.SetReadDeadline(time.Now())
}

// ----------------------------------------------------------------------
// per-flow engine.UDPConn
// ----------------------------------------------------------------------

type udpFlow struct {
	relay      *socks5UDPRelay
	clientAddr netip.AddrPort
	dst        engine.Endpoint

	inbox chan []byte

	closeOnce sync.Once
	closeCh   chan struct{}
	closed    atomic.Bool
}

func newUDPFlow(relay *socks5UDPRelay, client netip.AddrPort, dst engine.Endpoint) *udpFlow {
	return &udpFlow{
		relay:      relay,
		clientAddr: client,
		dst:        dst,
		inbox:      make(chan []byte, 256),
		closeCh:    make(chan struct{}),
	}
}

func (f *udpFlow) feedFromClient(payload []byte) {
	if f.closed.Load() {
		return
	}
	cp := append([]byte(nil), payload...)
	select {
	case f.inbox <- cp:
	case <-f.closeCh:
	default:
		select {
		case <-f.inbox:
		default:
		}
		select {
		case f.inbox <- cp:
		default:
		}
	}
}

func (f *udpFlow) ReadFrom(buf []byte) (int, engine.Endpoint, error) {
	select {
	case b, ok := <-f.inbox:
		if !ok {
			return 0, engine.Endpoint{}, io.EOF
		}
		n := copy(buf, b)
		return n, f.dst, nil
	case <-f.closeCh:
		return 0, engine.Endpoint{}, io.EOF
	}
}

// WriteTo wraps the upstream-supplied payload in a SOCKS5 UDP header
// (using realRemote as the apparent source) and writes it back to
// the client over the relay's UDP socket.
//
// The client may now legitimately observe replies originating from
// addresses different from the original dst — that's exactly what
// STUN / Full-Cone behaviour requires.
func (f *udpFlow) WriteTo(payload []byte, realRemote engine.Endpoint) error {
	if f.closed.Load() {
		return io.ErrClosedPipe
	}
	header := buildSocksUDPHeader(realRemote)
	pkt := make([]byte, 0, len(header)+len(payload))
	pkt = append(pkt, header...)
	pkt = append(pkt, payload...)
	_, err := f.relay.udpConn.WriteToUDPAddrPort(pkt, f.clientAddr)
	return err
}

func (f *udpFlow) Close() error {
	f.close()
	return nil
}

func (f *udpFlow) close() {
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		close(f.closeCh)
		close(f.inbox)
	})
}

var _ engine.UDPConn = (*udpFlow)(nil)

// ----------------------------------------------------------------------
// SOCKS5 UDP header codecs
// ----------------------------------------------------------------------

// parseSocksUDPAddr parses an address starting at buf[0]=atyp and
// returns the parsed endpoint plus how many bytes after the atyp
// byte were consumed.
func parseSocksUDPAddr(buf []byte, atyp byte) (engine.Endpoint, int, error) {
	switch atyp {
	case atypIPv4:
		if len(buf) < 1+4+2 {
			return engine.Endpoint{}, 0, errors.New("short IPv4")
		}
		var arr [4]byte
		copy(arr[:], buf[1:5])
		port := binary.BigEndian.Uint16(buf[5:7])
		ap := netip.AddrPortFrom(netip.AddrFrom4(arr), port)
		return engine.Endpoint{Addr: ap, Port: port}, 4 + 2, nil
	case atypIPv6:
		if len(buf) < 1+16+2 {
			return engine.Endpoint{}, 0, errors.New("short IPv6")
		}
		var arr [16]byte
		copy(arr[:], buf[1:17])
		port := binary.BigEndian.Uint16(buf[17:19])
		ap := netip.AddrPortFrom(netip.AddrFrom16(arr), port)
		return engine.Endpoint{Addr: ap, Port: port}, 16 + 2, nil
	case atypDomain:
		if len(buf) < 2 {
			return engine.Endpoint{}, 0, errors.New("short domain len")
		}
		dlen := int(buf[1])
		if len(buf) < 2+dlen+2 {
			return engine.Endpoint{}, 0, errors.New("short domain")
		}
		host := string(buf[2 : 2+dlen])
		port := binary.BigEndian.Uint16(buf[2+dlen : 2+dlen+2])
		return engine.Endpoint{Domain: host, Port: port}, 1 + dlen + 2, nil
	default:
		return engine.Endpoint{}, 0, errors.New("unsupported atyp")
	}
}

func buildSocksUDPHeader(e engine.Endpoint) []byte {
	out := []byte{0x00, 0x00, 0x00}
	switch {
	case e.IsDomain():
		out = append(out, atypDomain, byte(len(e.Domain)))
		out = append(out, []byte(e.Domain)...)
		out = append(out, byte(e.Port>>8), byte(e.Port))
	case e.Addr.Addr().Is6():
		out = append(out, atypIPv6)
		ip := e.Addr.Addr().As16()
		out = append(out, ip[:]...)
		port := e.Addr.Port()
		out = append(out, byte(port>>8), byte(port))
	default:
		out = append(out, atypIPv4)
		ip := e.Addr.Addr().Unmap().As4()
		out = append(out, ip[:]...)
		port := e.Addr.Port()
		out = append(out, byte(port>>8), byte(port))
	}
	return out
}
