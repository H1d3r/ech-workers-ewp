// Package engine is the unified per-process coordinator for inbound
// traffic, outbound dialing, and routing.
//
// One binary, one Engine. Whether the deployment is a "client" (TUN
// inbound + ewp-client outbound), a "server" (ewp-server inbound +
// direct outbound), or a relay (ewp-server inbound + ewp-client
// outbound) is purely a configuration choice. The Engine itself does
// not distinguish.
//
// All v2 protocol bytes pass through protocol/ewp/v2 SecureStream.
// The Engine and its Inbound/Outbound implementations carry only
// plaintext application bytes (TCP byte streams, UDP datagrams)
// between Inbound and Outbound; encryption happens inside the
// SecureStream that Outbound (or Inbound, on the server side) wraps.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// Endpoint identifies a traffic peer. Either Addr (IP+Port) or
// Domain+Port is meaningful, never both.
//
// Domain takes precedence whenever non-empty: this lets an Inbound
// preserve the original DNS name (e.g. via FakeIP reverse lookup) so
// the Outbound can resolve it under its own DNS policy.
type Endpoint struct {
	Addr   netip.AddrPort
	Domain string
	Port   uint16
}

func (e Endpoint) IsDomain() bool { return e.Domain != "" }

func (e Endpoint) String() string {
	if e.IsDomain() {
		return fmt.Sprintf("%s:%d", e.Domain, e.Port)
	}
	return e.Addr.String()
}

// UDPConn is the abstraction Inbound/Outbound exchange to carry UDP
// datagrams. It is intentionally narrower than net.PacketConn because
// it must work both on real OS sockets and on EWP v2 sub-sessions
// (which do not have a single peer address).
//
// ReadFrom returns the real source address of the datagram (the
// "real-remote", not a FakeIP). This is the linchpin of correct
// Full-Cone NAT and STUN consistency.
type UDPConn interface {
	WriteTo(payload []byte, dst Endpoint) error
	ReadFrom(buf []byte) (n int, src Endpoint, err error)
	Close() error
}

// InboundHandler is what an Inbound calls when it has a new flow.
//
// One Engine instance implements this and dispatches to the chosen
// Outbound based on the Router policy.
type InboundHandler interface {
	HandleTCP(ctx context.Context, src, dst Endpoint, conn TCPConn) error
	HandleUDP(ctx context.Context, src, dst Endpoint, conn UDPConn) error
}

// TCPConn is the byte-stream abstraction. It is io.ReadWriteCloser
// plus a couple of optional helpers; the engine never type-asserts
// for these helpers.
type TCPConn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Inbound accepts traffic from somewhere outside the EWP universe
// (TUN device, SOCKS5 listener, EWP server listener) and feeds it to
// an InboundHandler.
type Inbound interface {
	Tag() string
	Start(ctx context.Context, h InboundHandler) error
	Close() error
}

// Outbound dials traffic out from the engine.
type Outbound interface {
	Tag() string
	DialTCP(ctx context.Context, dst Endpoint) (TCPConn, error)
	DialUDP(ctx context.Context, dst Endpoint) (UDPConn, error)
	Close() error
}

// Router decides which Outbound a particular flow goes to.
//
// Returning "" rejects the flow.
type Router interface {
	Route(src, dst Endpoint, isUDP bool) (outboundTag string)
}

// StaticRouter routes every flow to a single named outbound.
//
// Useful for the smallest deployments and as the bootstrap router
// during early v2 development. Real rule-based routing arrives in a
// later commit.
type StaticRouter struct {
	Tag string
}

func (r *StaticRouter) Route(_, _ Endpoint, _ bool) string { return r.Tag }

// Engine is the per-process coordinator.
type Engine struct {
	mu        sync.RWMutex
	inbounds  []Inbound
	outbounds map[string]Outbound
	router    Router
}

// New constructs an empty Engine. Use Add* methods then Start.
func New(router Router) *Engine {
	if router == nil {
		router = &StaticRouter{}
	}
	return &Engine{
		outbounds: make(map[string]Outbound),
		router:    router,
	}
}

// AddInbound registers an Inbound. Tags MUST be unique among inbounds.
func (e *Engine) AddInbound(in Inbound) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, existing := range e.inbounds {
		if existing.Tag() == in.Tag() {
			return fmt.Errorf("engine: duplicate inbound tag %q", in.Tag())
		}
	}
	e.inbounds = append(e.inbounds, in)
	return nil
}

// AddOutbound registers an Outbound. Tags MUST be unique.
func (e *Engine) AddOutbound(out Outbound) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.outbounds[out.Tag()]; exists {
		return fmt.Errorf("engine: duplicate outbound tag %q", out.Tag())
	}
	e.outbounds[out.Tag()] = out
	return nil
}

// Start fires up every registered Inbound and blocks until ctx is
// cancelled. Each Inbound runs in its own goroutine.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.RLock()
	inbounds := append([]Inbound(nil), e.inbounds...)
	e.mu.RUnlock()

	if len(inbounds) == 0 {
		return errors.New("engine: no inbounds registered")
	}

	errCh := make(chan error, len(inbounds))
	var wg sync.WaitGroup
	for _, in := range inbounds {
		in := in
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := in.Start(ctx, e); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("inbound %q: %w", in.Tag(), err)
			}
		}()
	}

	<-ctx.Done()
	wg.Wait()
	close(errCh)

	var combined error
	for err := range errCh {
		if combined == nil {
			combined = err
		} else {
			combined = fmt.Errorf("%w; %v", combined, err)
		}
	}
	return combined
}

// Close shuts down all inbounds and outbounds. Idempotent per
// underlying implementation.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var first error
	for _, in := range e.inbounds {
		if err := in.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, out := range e.outbounds {
		if err := out.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// HandleTCP implements InboundHandler.
func (e *Engine) HandleTCP(ctx context.Context, src, dst Endpoint, conn TCPConn) error {
	tag := e.router.Route(src, dst, false)
	out, err := e.lookupOutbound(tag)
	if err != nil {
		_ = conn.Close()
		return err
	}
	remote, err := out.DialTCP(ctx, dst)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("dial TCP via %q: %w", tag, err)
	}
	go pipeTCP(conn, remote)
	return nil
}

// HandleUDP implements InboundHandler.
func (e *Engine) HandleUDP(ctx context.Context, src, dst Endpoint, conn UDPConn) error {
	tag := e.router.Route(src, dst, true)
	out, err := e.lookupOutbound(tag)
	if err != nil {
		_ = conn.Close()
		return err
	}
	remote, err := out.DialUDP(ctx, dst)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("dial UDP via %q: %w", tag, err)
	}
	go pipeUDP(conn, remote)
	return nil
}

// OutboundByTag returns the registered outbound for the given tag,
// or nil if no such outbound is registered. Useful for diagnostic
// tools (e.g. the probe-nat subcommand) that need to talk to a
// specific outbound by name.
func (e *Engine) OutboundByTag(tag string) Outbound {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.outbounds[tag]
}

func (e *Engine) lookupOutbound(tag string) (Outbound, error) {
	if tag == "" {
		return nil, errors.New("engine: router returned empty outbound tag (flow rejected)")
	}
	e.mu.RLock()
	out, ok := e.outbounds[tag]
	e.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("engine: outbound %q not registered", tag)
	}
	return out, nil
}
