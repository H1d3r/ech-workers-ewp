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

// serverSub is the engine.UDPConn handed to the engine for one
// client-initiated UDP sub-session.
//
// Direction translation (vs the client-side udpSub in
// outbound/ewpclient):
//
//   - "ReadFrom" by the engine returns the next client datagram (=
//     coming from the SecureStream). The src returned is the
//     sub-session's default destination (i.e. what the client wrote
//     in UDP_NEW), so the outbound knows where to send upstream.
//
//   - "WriteTo" by the engine carries an upstream reply (= going
//     back to the client via the SecureStream). The realRemote arg
//     is whatever the outbound observed; we faithfully encode it
//     into the UDP_DATA frame's meta.Address. This is the wire-side
//     half of the "Full-Cone NAT preservation" property.
type serverSub struct {
	gid        [8]byte
	ss         *v2.SecureStream
	defaultDst engine.Endpoint

	upstream chan upstreamDgram

	closeOnce sync.Once
	doneCh    chan struct{}
	closed    atomic.Bool
}

type upstreamDgram struct {
	payload []byte
}

func newServerSub(ctx context.Context, gid [8]byte, ss *v2.SecureStream, dst engine.Endpoint) *serverSub {
	s := &serverSub{
		gid:        gid,
		ss:         ss,
		defaultDst: dst,
		upstream:   make(chan upstreamDgram, 256),
		doneCh:     make(chan struct{}),
	}
	go func() {
		<-ctx.Done()
		s.terminate()
	}()
	return s
}

func (s *serverSub) sendUpstream(ev *v2.Event) {
	if s.closed.Load() {
		return
	}
	cp := append([]byte(nil), ev.Payload...)
	select {
	case s.upstream <- upstreamDgram{payload: cp}:
	case <-s.doneCh:
	default:
		// Queue saturated; drop oldest.
		select {
		case <-s.upstream:
		default:
		}
		select {
		case s.upstream <- upstreamDgram{payload: cp}:
		default:
		}
	}
}

func (s *serverSub) ReadFrom(buf []byte) (int, engine.Endpoint, error) {
	select {
	case dg, ok := <-s.upstream:
		if !ok {
			return 0, engine.Endpoint{}, io.EOF
		}
		n := copy(buf, dg.payload)
		// Tell the outbound where the client wanted this to go.
		// engine.pipeUDP forwards (in -> out) by passing this
		// returned Endpoint into out.WriteTo as the dst. For direct
		// outbound this lands as the real upstream address; for
		// chained ewpclient outbound this becomes the v2.Address in
		// UDP_DATA meta. Either way it's correct.
		return n, s.defaultDst, nil
	case <-s.doneCh:
		return 0, engine.Endpoint{}, io.EOF
	}
}

// WriteTo carries an upstream reply back to the client. realRemote is
// the source the outbound observed; we encode it into the frame meta.
func (s *serverSub) WriteTo(payload []byte, realRemote engine.Endpoint) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	target := v2.Address{}
	if realRemote.IsDomain() {
		target = v2.Address{Domain: realRemote.Domain, Port: realRemote.Port}
	} else if realRemote.Addr.IsValid() {
		target = v2.Address{Addr: realRemote.Addr}
	}
	if err := s.ss.SendUDPData(s.gid, target, payload); err != nil {
		s.terminate()
		return err
	}
	return nil
}

func (s *serverSub) Close() error {
	s.terminate()
	return nil
}

func (s *serverSub) terminate() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.doneCh)
		close(s.upstream)
	})
}

// observedAddr returns the externally-observable address of the
// sub-session for inclusion in a UDP_PROBE_RESP. For now this is a
// best-effort placeholder: we report the default destination.
//
// A future enhancement is to plumb a STUN-resolved public address
// from the outbound's local socket. For ewpserver-as-relay (where
// the outbound is ewpclient), the right answer is the upstream
// server's PROBE_RESP — which means propagating PROBE_REQ across the
// engine pipe. Out of scope for commit 7.
func (s *serverSub) observedAddr() v2.Address {
	if s.defaultDst.IsDomain() {
		return v2.Address{Domain: s.defaultDst.Domain, Port: s.defaultDst.Port}
	}
	return v2.Address{Addr: s.defaultDst.Addr}
}

// Compile-time check.
var _ engine.UDPConn = (*serverSub)(nil)

// streamConn implements engine.TCPConn for one TCP-mode SecureStream.
//
// Read returns whatever payload the recvLoop delivered via deliver();
// Write sends one TCP_DATA frame.
type streamConn struct {
	ss *v2.SecureStream

	mu      sync.Mutex
	leftover []byte
	inbox   chan []byte

	closeOnce sync.Once
	doneCh    chan struct{}
}

func newStreamConn(ss *v2.SecureStream) *streamConn {
	return &streamConn{
		ss:     ss,
		inbox:  make(chan []byte, 256),
		doneCh: make(chan struct{}),
	}
}

func (c *streamConn) deliver(payload []byte) {
	cp := append([]byte(nil), payload...)
	select {
	case c.inbox <- cp:
	case <-c.doneCh:
	}
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case b, ok := <-c.inbox:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, b)
		if n < len(b) {
			c.mu.Lock()
			c.leftover = append(c.leftover[:0], b[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.doneCh:
		return 0, io.EOF
	}
}

func (c *streamConn) Write(p []byte) (int, error) {
	if err := c.ss.SendTCPData(p); err != nil {
		c.terminate()
		return 0, err
	}
	return len(p), nil
}

func (c *streamConn) Close() error {
	c.terminate()
	return nil
}

func (c *streamConn) terminate() {
	c.closeOnce.Do(func() {
		close(c.doneCh)
		close(c.inbox)
	})
}

// Compile-time check.
var _ engine.TCPConn = (*streamConn)(nil)

// silence unused-import warnings if all log.V calls get optimised
// out by the compiler in some build tag combination.
var (
	_ = log.V
	_ = errors.New
	_ = netip.AddrPort{}
)
