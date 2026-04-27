package tun

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"ewp-core/dns"
	"ewp-core/engine"
)

// tunSocket is the engine.UDPConn handed to the engine for one
// TUN-side UDP flow. It is the single point in the system where
// FakeIP semantics meet Full-Cone NAT semantics.
//
// FakeIP flow rule
// ----------------
// If the original dst was a FakeIP address, the application is
// communicating with a *virtual* peer. To keep the application's
// socket happy, every reply written back to the TUN MUST carry
// `src = original dst` regardless of where the real reply actually
// came from upstream.
//
// Real-IP flow rule (Full-Cone, STUN)
// -----------------------------------
// If the original dst was a real IP, the application may legitimately
// receive replies from *any* real remote (this is the entire point of
// STUN consistency tests and ICE / WebRTC). Each reply MUST carry the
// real upstream src verbatim.
//
// One bit (`isFake`) decides which rule applies. The bit is fixed at
// flow creation time, since FakeIP and real-IP traffic for the same
// (src, dst) pair are mutually exclusive.
type tunSocket struct {
	tunWriter   udpResponseWriter
	originalSrc netip.AddrPort // app's source as seen on the TUN
	originalDst netip.AddrPort // app's destination as seen on the TUN
	dstEndpoint engine.Endpoint
	isFake      bool
	pool        *dns.FakeIPPool

	inbox chan inboundDgram

	closeOnce sync.Once
	closed    atomic.Bool
	closeCh   chan struct{}
}

type inboundDgram struct {
	payload []byte
	src     netip.AddrPort
}

func newTunSocket(
	tunWriter udpResponseWriter,
	originalSrc, originalDst netip.AddrPort,
	dstEP engine.Endpoint,
	pool *dns.FakeIPPool,
) *tunSocket {
	isFake := false
	if pool != nil && pool.IsFakeIP(originalDst.Addr()) {
		isFake = true
	}
	return &tunSocket{
		tunWriter:   tunWriter,
		originalSrc: originalSrc,
		originalDst: originalDst,
		dstEndpoint: dstEP,
		isFake:      isFake,
		pool:        pool,
		inbox:       make(chan inboundDgram, 256),
		closeCh:     make(chan struct{}),
	}
}

// feedFromTUN is called by Handler.HandleUDP for each datagram the
// gVisor stack delivers from the TUN application.
func (s *tunSocket) feedFromTUN(payload []byte, src netip.AddrPort) {
	if s.closed.Load() {
		return
	}
	cp := append([]byte(nil), payload...)
	select {
	case s.inbox <- inboundDgram{payload: cp, src: src}:
	case <-s.closeCh:
	default:
		// Inbox saturated. Drop oldest by draining one slot then
		// inserting; UDP loss tolerance is the entire point of UDP.
		select {
		case <-s.inbox:
		default:
		}
		select {
		case s.inbox <- inboundDgram{payload: cp, src: src}:
		default:
		}
	}
}

// ReadFrom is invoked by engine.pipeUDP's "inbound -> outbound"
// goroutine. We surface the original engine.Endpoint dst so the
// outbound knows where the application thinks it is sending — for
// ewpclient this becomes the v2.Address inside UDP_NEW / UDP_DATA.
func (s *tunSocket) ReadFrom(buf []byte) (int, engine.Endpoint, error) {
	select {
	case dg, ok := <-s.inbox:
		if !ok {
			return 0, engine.Endpoint{}, io.EOF
		}
		n := copy(buf, dg.payload)
		// engine.pipeUDP forwards (in -> out) by passing the result
		// of ReadFrom into out.WriteTo as `dst`. We want the outbound
		// to send to the application's intended dst, so return that.
		return n, s.dstEndpoint, nil
	case <-s.closeCh:
		return 0, engine.Endpoint{}, io.EOF
	}
}

// WriteTo is invoked by engine.pipeUDP's "outbound -> inbound"
// goroutine for every reply datagram. realSrc is whatever the
// outbound observed (for ewpclient: the server-reported real remote;
// for direct: the OS-level src).
//
// This is where the FakeIP × Full-Cone split lives.
func (s *tunSocket) WriteTo(payload []byte, realSrc engine.Endpoint) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}

	var srcAddr net.Addr
	switch {
	case s.isFake:
		// FakeIP flow: app expects replies from `originalDst`.
		srcAddr = net.UDPAddrFromAddrPort(s.originalDst)

	case realSrc.IsDomain():
		// Real-IP flow but the outbound returned a domain Endpoint.
		// Resolve to the originalDst's IP so the application socket
		// is happy. This shouldn't normally happen for direct/
		// ewpclient outbounds, which both surface real addresses,
		// but kept as a safety fallback.
		srcAddr = net.UDPAddrFromAddrPort(s.originalDst)

	case realSrc.Addr.IsValid():
		// Real-IP flow: forward the real upstream src verbatim. This
		// is what enables Full-Cone NAT: a STUN consistency probe
		// against four servers will see four distinct src addresses
		// here and surface them correctly to the application.
		srcAddr = net.UDPAddrFromAddrPort(realSrc.Addr)

	default:
		srcAddr = net.UDPAddrFromAddrPort(s.originalDst)
	}

	_, err := s.tunWriter.WriteTo(payload, srcAddr)
	return err
}

func (s *tunSocket) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.closeCh)
	})
	return nil
}

// Compile-time check: tunSocket satisfies engine.UDPConn.
var _ engine.UDPConn = (*tunSocket)(nil)
