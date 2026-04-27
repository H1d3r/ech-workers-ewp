// Package direct is the bypass-everything Outbound: it dials the
// remote endpoint with the operating system's network stack.
//
// In v2 it accepts an optional dns.AsyncResolver so that domain
// resolution can avoid the OS resolver entirely (which on a server
// box typically goes through the local ISP — defeating the privacy
// posture of the rest of the project). When no resolver is supplied
// it falls back to the OS resolver, mirroring v1 behaviour.
package direct

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"ewp-core/dns"
	"ewp-core/engine"
)

// Outbound implements engine.Outbound by dialing directly with
// net.Dial / net.ListenUDP.
type Outbound struct {
	tag      string
	dialer   *net.Dialer
	resolver *dns.AsyncResolver // nil = OS resolver
}

// New builds a direct outbound with sensible defaults.
//
// timeout governs both TCP dial timeout and the DNS resolution step.
func New(tag string, timeout time.Duration) *Outbound {
	if tag == "" {
		tag = "direct"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Outbound{
		tag: tag,
		dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// SetResolver attaches an AsyncResolver. After this is called the
// outbound stops talking to the OS resolver entirely; all domain
// resolutions go through DoH (with caching, deduplication, and a
// worker-pool concurrency cap).
//
// Pass nil to remove the resolver and revert to OS-resolver
// behaviour.
func (o *Outbound) SetResolver(r *dns.AsyncResolver) { o.resolver = r }

// Tag implements engine.Outbound.
func (o *Outbound) Tag() string { return o.tag }

// DialTCP implements engine.Outbound.
func (o *Outbound) DialTCP(ctx context.Context, dst engine.Endpoint) (engine.TCPConn, error) {
	addr, err := o.resolveEndpoint(ctx, dst)
	if err != nil {
		return nil, err
	}
	c, err := o.dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("direct: dial %s: %w", addr, err)
	}
	return c, nil
}

// DialUDP implements engine.Outbound. We use ListenUDP(":0") rather
// than DialUDP so that one local socket can write to multiple remotes
// (Full-Cone NAT and STUN consistency require this).
func (o *Outbound) DialUDP(ctx context.Context, dst engine.Endpoint) (engine.UDPConn, error) {
	defaultRemote, err := o.resolveEndpoint(ctx, dst)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("direct: listen udp: %w", err)
	}
	return &udpAdapter{
		conn:          conn,
		defaultRemote: net.UDPAddrFromAddrPort(defaultRemote),
		resolver:      o.resolver,
	}, nil
}

// Close releases shared resources. The Outbound itself holds no
// per-connection state beyond the dialer template.
func (o *Outbound) Close() error { return nil }

// resolveEndpoint turns an engine.Endpoint into a netip.AddrPort.
// Domains go through the AsyncResolver if one is attached; otherwise
// through the OS resolver via net.Resolver.
func (o *Outbound) resolveEndpoint(ctx context.Context, e engine.Endpoint) (netip.AddrPort, error) {
	if e.IsDomain() {
		port := e.Port
		if port == 0 {
			port = e.Addr.Port()
		}
		if port == 0 {
			return netip.AddrPort{}, errors.New("direct: zero port for domain endpoint")
		}
		if o.resolver != nil {
			ip, err := o.resolver.Resolve(ctx, e.Domain, false)
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("direct: resolve %s: %w", e.Domain, err)
			}
			return netip.AddrPortFrom(ip, port), nil
		}
		// OS resolver fallback.
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", e.Domain)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("direct: os-resolve %s: %w", e.Domain, err)
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, fmt.Errorf("direct: no addresses for %s", e.Domain)
		}
		return netip.AddrPortFrom(ips[0].Unmap(), port), nil
	}
	if !e.Addr.IsValid() {
		return netip.AddrPort{}, errors.New("direct: endpoint has neither domain nor valid address")
	}
	return e.Addr, nil
}

// ----------------------------------------------------------------------
// UDP adapter
// ----------------------------------------------------------------------

// udpAdapter wraps a *net.UDPConn so it speaks engine.UDPConn.
//
// defaultRemote is the destination supplied at DialUDP time and is
// used when the caller passes an Endpoint with a zero address (e.g.
// EWP UDP_DATA frames that elect to use the sub-session default).
type udpAdapter struct {
	conn          *net.UDPConn
	defaultRemote *net.UDPAddr
	resolver      *dns.AsyncResolver

	closed  bool
	closeMu sync.Mutex
}

// WriteTo sends a payload to the supplied destination. Per-frame
// domain targets are resolved via the same resolver as the outbound;
// IP targets bypass DNS entirely.
func (a *udpAdapter) WriteTo(payload []byte, dst engine.Endpoint) error {
	target, err := a.resolveTo(dst)
	if err != nil {
		return err
	}
	_, err = a.conn.WriteToUDP(payload, target)
	return err
}

func (a *udpAdapter) resolveTo(e engine.Endpoint) (*net.UDPAddr, error) {
	if e.IsDomain() {
		port := e.Port
		if port == 0 && a.defaultRemote != nil {
			port = uint16(a.defaultRemote.Port)
		}
		if port == 0 {
			return nil, errors.New("direct: zero port")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var ip netip.Addr
		var err error
		if a.resolver != nil {
			ip, err = a.resolver.Resolve(ctx, e.Domain, false)
		} else {
			ips, e2 := net.DefaultResolver.LookupNetIP(ctx, "ip", e.Domain)
			if e2 != nil {
				err = e2
			} else if len(ips) > 0 {
				ip = ips[0].Unmap()
			} else {
				err = fmt.Errorf("no addresses for %s", e.Domain)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("direct: resolve %s: %w", e.Domain, err)
		}
		ap := netip.AddrPortFrom(ip, port)
		return net.UDPAddrFromAddrPort(ap), nil
	}
	if !e.Addr.IsValid() {
		if a.defaultRemote != nil {
			return a.defaultRemote, nil
		}
		return nil, errors.New("direct: empty UDP target")
	}
	return net.UDPAddrFromAddrPort(e.Addr), nil
}

func (a *udpAdapter) ReadFrom(buf []byte) (int, engine.Endpoint, error) {
	n, src, err := a.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return 0, engine.Endpoint{}, err
	}
	return n, engine.Endpoint{Addr: src, Port: src.Port()}, nil
}

func (a *udpAdapter) Close() error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return a.conn.Close()
}

// Compile-time interface checks.
var (
	_ engine.Outbound = (*Outbound)(nil)
	_ engine.UDPConn  = (*udpAdapter)(nil)
	_ engine.TCPConn  = (net.Conn)(nil) // io.RWC subset
)
