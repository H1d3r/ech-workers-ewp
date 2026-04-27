package ewpclient

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"ewp-core/engine"
	"ewp-core/log"
	v2 "ewp-core/protocol/ewp/v2"
)

// tunnel is one SecureStream-backed multi-sub-session container,
// shared by every UDP flow originating at the same inbound src.
type tunnel struct {
	ss *v2.SecureStream

	mu     sync.Mutex
	subs   map[[8]byte]*udpSub
	closed atomic.Bool

	onClose func()
}

func newTunnel(ss *v2.SecureStream, onClose func()) *tunnel {
	return &tunnel{
		ss:      ss,
		subs:    make(map[[8]byte]*udpSub),
		onClose: onClose,
	}
}

func (t *tunnel) alive() bool { return !t.closed.Load() }

func (t *tunnel) close() {
	if t.closed.Swap(true) {
		return
	}
	_ = t.ss.Close()
	t.mu.Lock()
	for gid, s := range t.subs {
		s.terminate(io.ErrClosedPipe)
		delete(t.subs, gid)
	}
	t.mu.Unlock()
	if t.onClose != nil {
		// Defer to avoid deadlock if onClose tries to take Outbound.mu
		// while we hold tunnel.mu (we don't, but defensive).
		go t.onClose()
	}
}

// openSub creates a fresh sub-session for a destination. The first
// frame ever sent via this sub will be UDP_NEW; later ones use
// UDP_DATA. The sub-session also receives all inbound frames carrying
// its GlobalID — including those whose meta address is some other
// "real remote" (e.g. STUN reflective response).
func (t *tunnel) openSub(gid [8]byte, defaultDst v2.Address) *udpSub {
	sub := &udpSub{
		tunnel:     t,
		gid:        gid,
		defaultDst: defaultDst,
		incoming:   make(chan udpRecvFrame, 256),
		closeCh:    make(chan struct{}),
	}
	t.mu.Lock()
	if t.closed.Load() {
		t.mu.Unlock()
		sub.terminate(io.ErrClosedPipe)
		return sub
	}
	t.subs[gid] = sub
	t.mu.Unlock()
	return sub
}

func (t *tunnel) removeSub(gid [8]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.subs, gid)
}

func (t *tunnel) lookupSub(gid [8]byte) (*udpSub, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.subs[gid]
	return s, ok
}

// recvLoop is the single goroutine that drains the SecureStream and
// dispatches each frame to the correct sub-session. SecureStream.Recv
// must not be called from any other goroutine.
func (t *tunnel) recvLoop() {
	defer t.close()
	for {
		ev, err := t.ss.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				log.V("[ewpclient] SecureStream recv error: %v", err)
			}
			return
		}
		switch ev.Type {
		case v2.FrameUDPData, v2.FrameUDPNew:
			sub, ok := t.lookupSub(ev.GlobalID)
			if !ok {
				// Server replied for a sub we already closed; drop.
				continue
			}
			sub.deliver(ev)
		case v2.FrameUDPEnd:
			sub, ok := t.lookupSub(ev.GlobalID)
			if ok {
				sub.terminate(io.EOF)
			}
		case v2.FrameUDPProbeResp:
			sub, ok := t.lookupSub(ev.GlobalID)
			if ok {
				sub.deliverProbe(ev)
			}
		case v2.FramePing:
			_ = t.ss.SendPong(ev.Payload)
		case v2.FramePong, v2.FramePaddingOnly:
			// ignored
		default:
			log.V("[ewpclient] unexpected frame type %d on UDP tunnel", ev.Type)
		}
	}
}

// ----------------------------------------------------------------------
// udpSub implements engine.UDPConn for one sub-session
// ----------------------------------------------------------------------

type udpRecvFrame struct {
	src     v2.Address // server-reported real remote
	payload []byte
}

type udpSub struct {
	tunnel     *tunnel
	gid        [8]byte
	defaultDst v2.Address

	incoming chan udpRecvFrame
	probe    atomic.Pointer[v2.Address]

	closeOnce sync.Once
	closeCh   chan struct{}

	// firstFrame is true until the first SendTo, controlling whether
	// we emit UDP_NEW or UDP_DATA on the wire.
	firstFrame atomic.Bool
}

func (s *udpSub) WriteTo(payload []byte, dst engine.Endpoint) error {
	if s.isClosed() {
		return io.ErrClosedPipe
	}
	target, err := endpointToAddress(dst)
	// Tolerate empty Endpoint by falling back to the sub's default
	// destination — callers that don't track per-frame targets (e.g.
	// engine.pipeUDP forwarding TUN datagrams) just write to dst they
	// were handed at DialUDP time.
	if err != nil {
		target = s.defaultDst
	}

	if s.firstFrame.CompareAndSwap(false, true) {
		// UDP_NEW carries the initial datagram and binds the sub
		// to its default target on the server.
		s.defaultDst = target
		return s.tunnel.ss.SendUDPNew(s.gid, target, payload)
	}
	// Per-frame target on UDP_DATA is allowed by the spec; the
	// server uses it for THIS frame only.
	return s.tunnel.ss.SendUDPData(s.gid, target, payload)
}

func (s *udpSub) ReadFrom(buf []byte) (int, engine.Endpoint, error) {
	select {
	case f, ok := <-s.incoming:
		if !ok {
			return 0, engine.Endpoint{}, io.EOF
		}
		n := copy(buf, f.payload)
		return n, addressToEndpoint(f.src), nil
	case <-s.closeCh:
		return 0, engine.Endpoint{}, io.EOF
	}
}

// Probe issues a UDP_PROBE_REQ and waits for the matching response.
// Surfaced for STUN consistency tooling and tests; not part of
// engine.UDPConn (engine doesn't need it).
func (s *udpSub) Probe() (v2.Address, error) {
	if err := s.tunnel.ss.SendProbeReq(s.gid); err != nil {
		return v2.Address{}, err
	}
	select {
	case <-s.closeCh:
		return v2.Address{}, io.ErrClosedPipe
	}
}

func (s *udpSub) Close() error {
	s.terminate(nil)
	if s.tunnel.alive() {
		// Tell the server this sub is gone.
		_ = s.tunnel.ss.SendUDPEnd(s.gid)
	}
	s.tunnel.removeSub(s.gid)
	return nil
}

func (s *udpSub) deliver(ev *v2.Event) {
	src := s.defaultDst
	if ev.HasAddr {
		src = ev.Address
	}
	select {
	case s.incoming <- udpRecvFrame{src: src, payload: ev.Payload}:
	case <-s.closeCh:
	default:
		// Inbox full — best-effort drop. Datagram semantics tolerate
		// loss; better than blocking the whole tunnel's recvLoop.
		log.V("[ewpclient] sub %x inbox full; dropping frame", s.gid)
	}
}

func (s *udpSub) deliverProbe(ev *v2.Event) {
	if ev.HasAddr {
		addr := ev.Address
		s.probe.Store(&addr)
	}
}

func (s *udpSub) terminate(err error) {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		close(s.incoming)
	})
}

func (s *udpSub) isClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

// Compile-time check.
var _ engine.UDPConn = (*udpSub)(nil)
