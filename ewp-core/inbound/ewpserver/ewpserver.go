// Package ewpserver is the Inbound that accepts EWP v2 tunnels from
// remote peers and dispatches the per-tunnel flows into the Engine.
//
// Architectural mirror image of outbound/ewpclient: client-side
// tunnels are dialed by ewpclient.Outbound; server-side tunnels are
// accepted by ewpserver.Inbound. Both sides use the same v2
// SecureStream and frame codec — that's the "unified kernel" the
// project commits to.
//
// One ewpserver.Inbound is wired to one transport listener (WS, gRPC,
// H3-gRPC-Web, xhttp stream-one). Multiple Inbounds may coexist in
// the same Engine (e.g. listen on both WS:443 and H3:443).
package ewpserver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"ewp-core/engine"
	"ewp-core/log"
	v2 "ewp-core/protocol/ewp/v2"
	"ewp-core/transport"
)

// Listener is the narrow contract a transport server must satisfy in
// order to be plugged into ewpserver.
//
// Each Accept returns one fresh inbound transport.TunnelConn whose
// FIRST inbound message will be the EWP v2 ClientHello.
//
// Listeners that need an explicit start (e.g. push-based HTTP servers
// wrapped in a pull adapter) may additionally implement Runner; if
// they do, Inbound.Start will invoke run(ctx) before the accept loop.
type Listener interface {
	Accept() (transport.TunnelConn, error)
	Close() error
	Addr() string
}

// Runner is an optional interface; listeners that need a kickstart
// implement it. Most direct listeners do not.
type Runner interface {
	run(ctx context.Context)
}

// Inbound implements engine.Inbound for an EWP v2 server endpoint.
type Inbound struct {
	tag      string
	listener Listener
	uuids    [][v2.UUIDLen]byte

	mu        sync.Mutex
	closed    bool
	sessions  map[*serverSession]struct{}
	reflexive v2.Address // public mapping reported in UDP_PROBE_RESP; zero = use defaultDst
}

// SetReflexive sets the publicly-observable address that this server
// reports in UDP_PROBE_RESP frames. Typically discovered with the
// common/stun package at startup. Setting an invalid address (the
// zero value) restores the previous behaviour of echoing the
// sub-session's default destination.
//
// Concurrency: safe to call at any time; existing sessions pick up
// the new value on the next probe.
func (i *Inbound) SetReflexive(ip [16]byte, port uint16, isIPv6 bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if isIPv6 {
		i.reflexive = v2.Address{Addr: addrPortFromBytes16(ip, port)}
	} else {
		var ip4 [4]byte
		copy(ip4[:], ip[12:16])
		i.reflexive = v2.Address{Addr: addrPortFromBytes4(ip4, port)}
	}
}

// reflexiveAddr returns the configured reflexive (or the zero
// Address if none was set). Read under lock.
func (i *Inbound) reflexiveAddr() v2.Address {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.reflexive
}

// New constructs an ewpserver.Inbound.
//
// uuids is the set of PSKs accepted at the handshake. Linear search
// is intentional (constant-time over the typical < 64 UUID range).
func New(tag string, listener Listener, uuids [][v2.UUIDLen]byte) (*Inbound, error) {
	if listener == nil {
		return nil, errors.New("ewpserver: listener is nil")
	}
	if len(uuids) == 0 {
		return nil, errors.New("ewpserver: at least one UUID is required")
	}
	if tag == "" {
		tag = "ewpserver"
	}
	return &Inbound{
		tag:      tag,
		listener: listener,
		uuids:    uuids,
		sessions: make(map[*serverSession]struct{}),
	}, nil
}

// Tag implements engine.Inbound.
func (i *Inbound) Tag() string { return i.tag }

// Start implements engine.Inbound. Blocks until ctx is cancelled or
// the listener returns a fatal error.
func (i *Inbound) Start(ctx context.Context, h engine.InboundHandler) error {
	log.Printf("[ewpserver] %q listening on %s", i.tag, i.listener.Addr())
	defer log.Printf("[ewpserver] %q stopped", i.tag)

	if r, ok := i.listener.(Runner); ok {
		r.run(ctx)
	}

	go func() {
		<-ctx.Done()
		_ = i.listener.Close()
	}()

	lookup := v2.MakeUUIDLookup(i.uuids)
	for {
		tc, err := i.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ewpserver: accept: %w", err)
		}
		go i.serveTunnel(ctx, h, tc, lookup)
	}
}

// Close implements engine.Inbound.
func (i *Inbound) Close() error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	sessions := make([]*serverSession, 0, len(i.sessions))
	for s := range i.sessions {
		sessions = append(sessions, s)
	}
	i.sessions = nil
	i.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}
	_ = i.listener.Close()
	return nil
}

// serveTunnel handshakes one inbound TunnelConn, builds a
// SecureStream, registers a serverSession, and starts its recv loop.
func (i *Inbound) serveTunnel(ctx context.Context, h engine.InboundHandler, tc transport.TunnelConn, lookup v2.UUIDLookup) {
	hi, err := tc.ReadMessage()
	if err != nil {
		_ = tc.Close()
		log.V("[ewpserver] read ClientHello: %v", err)
		return
	}
	helloOut, res, err := v2.AcceptClientHello(hi, lookup)
	if err != nil {
		// No fake response; drop. The honest signal a probe gets is
		// the outer TLS layer.
		_ = tc.Close()
		log.V("[ewpserver] AcceptClientHello: %v", err)
		return
	}
	if err := tc.SendMessage(helloOut); err != nil {
		_ = tc.Close()
		log.V("[ewpserver] send ServerHello: %v", err)
		return
	}
	ss, err := v2.NewServerSecureStream(tc, res.Keys)
	if err != nil {
		_ = tc.Close()
		log.V("[ewpserver] NewServerSecureStream: %v", err)
		return
	}

	sess := newServerSession(ctx, h, ss, res.ClientHello)
	sess.reflexiveProvider = i.reflexiveAddr
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		sess.close()
		return
	}
	i.sessions[sess] = struct{}{}
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		delete(i.sessions, sess)
		i.mu.Unlock()
		sess.close()
	}()

	sess.recvLoop()
}
