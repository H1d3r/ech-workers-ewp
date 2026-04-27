package ewpserver

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"

	"ewp-core/engine"
	"ewp-core/log"
	v2 "ewp-core/protocol/ewp/v2"
)

// serverSession is one accepted EWP v2 tunnel: one SecureStream plus
// its multiplexed sub-sessions.
//
// Concurrency: recvLoop owns reads from the SecureStream; everything
// else (frame writes, sub-session map mutations) is serialised with
// the session-level mutex or per-sub-session locks.
type serverSession struct {
	ctx     context.Context
	cancel  context.CancelFunc
	handler engine.InboundHandler
	ss      *v2.SecureStream
	hello   *v2.ClientHello

	// Per-tunnel "client source" — synthesised from the inner UUID
	// so all sub-sessions on this tunnel share one engine.Endpoint
	// src. Outbounds may use this to multiplex back upstream.
	src engine.Endpoint

	mu   sync.Mutex
	subs map[[8]byte]*serverSub

	// One outbound v2.SecureStream may have at most one TCP flow
	// (the wire spec: Command set at handshake time). For TCP we
	// build a streamConn pair and call engine.HandleTCP exactly
	// once; subsequent TCP_DATA frames flow through the streamConn.
	tcp *streamConn

	// reflexiveProvider is wired by the parent Inbound; called on
	// every UDP_PROBE_REQ to learn the publicly-observable address
	// (typically populated at startup with common/stun).
	reflexiveProvider func() v2.Address

	closed atomic.Bool
}

// addrIsValid is a small helper used by the PROBE_REQ branch.
func addrIsValid(a v2.Address) bool {
	if a.Domain != "" {
		return true
	}
	return a.Addr.IsValid()
}

func newServerSession(ctx context.Context, h engine.InboundHandler, ss *v2.SecureStream, hello *v2.ClientHello) *serverSession {
	cctx, cancel := context.WithCancel(ctx)

	// Synthesise a stable per-tunnel src endpoint from the UUID.
	// The exact bytes don't matter to outbounds; what matters is
	// that two tunnels under the same UUID hash differently in
	// general (different ephemeral keys, different sub-session
	// IDs) — and that one tunnel's sub-sessions all share one src
	// (so ewpclient on the relay side multiplexes correctly).
	srcAddr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{
		hello.UUID[0], hello.UUID[1], hello.UUID[2], hello.UUID[3],
	}).Unmap(), uint16(hello.UUID[4])<<8|uint16(hello.UUID[5]))

	return &serverSession{
		ctx:     cctx,
		cancel:  cancel,
		handler: h,
		ss:      ss,
		hello:   hello,
		src:     engine.Endpoint{Addr: srcAddr, Port: srcAddr.Port()},
		subs:    make(map[[8]byte]*serverSub),
	}
}

func (s *serverSession) close() {
	if s.closed.Swap(true) {
		return
	}
	s.cancel()
	_ = s.ss.Close()
	s.mu.Lock()
	for gid, sub := range s.subs {
		sub.terminate()
		delete(s.subs, gid)
	}
	if s.tcp != nil {
		s.tcp.terminate()
	}
	s.mu.Unlock()
}

// recvLoop drains one SecureStream until error or close.
func (s *serverSession) recvLoop() {
	defer s.close()

	switch s.hello.Command {
	case v2.CommandTCP:
		s.startTCP()
	case v2.CommandUDP:
		// UDP sub-sessions are created lazily on UDP_NEW.
	default:
		log.V("[ewpserver] unsupported command 0x%02x", s.hello.Command)
		return
	}

	for {
		ev, err := s.ss.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				log.V("[ewpserver] recv: %v", err)
			}
			return
		}
		s.dispatch(ev)
	}
}

func (s *serverSession) dispatch(ev *v2.Event) {
	switch ev.Type {
	case v2.FrameTCPData:
		if s.tcp != nil {
			s.tcp.deliver(ev.Payload)
		}
	case v2.FrameUDPNew:
		s.openUDPSub(ev)
	case v2.FrameUDPData:
		sub := s.lookupSub(ev.GlobalID)
		if sub != nil {
			sub.sendUpstream(ev)
		} else {
			// Per spec, the server MAY drop UDP_DATA for unknown
			// GlobalIDs. We emit UDP_END so the client tears down
			// the orphan promptly.
			_ = s.ss.SendUDPEnd(ev.GlobalID)
		}
	case v2.FrameUDPEnd:
		sub := s.lookupSub(ev.GlobalID)
		if sub != nil {
			sub.terminate()
			s.removeSub(ev.GlobalID)
		}
	case v2.FrameUDPProbeReq:
		sub := s.lookupSub(ev.GlobalID)
		if sub != nil {
			// If the inbound has a STUN-discovered reflexive
			// address (from common/stun at startup), report that
			// — that's what clients see from the public Internet.
			// Otherwise fall back to the sub-session's default
			// destination, which at least tells the client we're
			// reachable but says nothing about NAT type.
			addr := v2.Address{}
			if s.reflexiveProvider != nil {
				addr = s.reflexiveProvider()
			}
			if !addrIsValid(addr) {
				addr = sub.observedAddr()
			}
			_ = s.ss.SendProbeResp(ev.GlobalID, addr)
		}
	case v2.FramePing:
		_ = s.ss.SendPong(ev.Payload)
	case v2.FramePong, v2.FramePaddingOnly:
		// ignored
	default:
		log.V("[ewpserver] unexpected frame type %d", ev.Type)
	}
}

// ----------------------------------------------------------------------
// TCP path
// ----------------------------------------------------------------------

func (s *serverSession) startTCP() {
	dst := endpointFromAddress(s.hello.Address)
	conn := newStreamConn(s.ss)
	s.mu.Lock()
	s.tcp = conn
	s.mu.Unlock()

	// Initial payload? The v2 ClientHello plaintext does not carry
	// any inline data; the application's first byte arrives in the
	// first TCP_DATA frame, which the recv loop will deliver.
	go func() {
		if err := s.handler.HandleTCP(s.ctx, s.src, dst, conn); err != nil {
			log.V("[ewpserver] HandleTCP: %v", err)
		}
	}()
}

// ----------------------------------------------------------------------
// UDP path
// ----------------------------------------------------------------------

func (s *serverSession) openUDPSub(ev *v2.Event) {
	if !ev.HasAddr {
		log.V("[ewpserver] UDP_NEW missing target")
		return
	}
	gid := ev.GlobalID
	dst := endpointFromAddress(ev.Address)

	sub := newServerSub(s.ctx, gid, s.ss, dst)

	s.mu.Lock()
	if _, exists := s.subs[gid]; exists {
		s.mu.Unlock()
		log.V("[ewpserver] UDP_NEW for already-open gid %x", gid)
		sub.terminate()
		return
	}
	s.subs[gid] = sub
	s.mu.Unlock()

	go func() {
		if err := s.handler.HandleUDP(s.ctx, s.src, dst, sub); err != nil {
			log.V("[ewpserver] HandleUDP: %v", err)
			sub.terminate()
			s.removeSub(gid)
			_ = s.ss.SendUDPEnd(gid)
			return
		}
	}()

	// Deliver any initial datagram immediately.
	if len(ev.Payload) > 0 {
		sub.sendUpstream(ev)
	}

	// Watch for sub termination from upstream side and emit UDP_END
	// to the peer (spec §5.2 M3 fix).
	go func() {
		<-sub.doneCh
		s.removeSub(gid)
		_ = s.ss.SendUDPEnd(gid)
	}()
}

func (s *serverSession) lookupSub(gid [8]byte) *serverSub {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subs[gid]
}

func (s *serverSession) removeSub(gid [8]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, gid)
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func endpointFromAddress(a v2.Address) engine.Endpoint {
	if a.IsDomain() {
		return engine.Endpoint{Domain: a.Domain, Port: a.Port}
	}
	return engine.Endpoint{Addr: a.Addr, Port: a.Addr.Port()}
}
