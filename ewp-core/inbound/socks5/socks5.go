// Package socks5 is an Inbound implementing the SOCKS5 protocol
// (RFC 1928 / RFC 1929) on top of the unified engine.
//
// Supported:
//   - methods: NO_AUTH (0x00) and USERNAME/PASSWORD (0x02)
//   - commands: CONNECT (0x01) and UDP_ASSOCIATE (0x03)
//   - address types: IPv4, IPv6, DOMAIN
//
// Unsupported (rejected):
//   - BIND command (rare, of marginal value for proxies)
//   - GSSAPI auth
package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"ewp-core/engine"
	"ewp-core/log"
)

// SOCKS5 wire constants (RFC 1928).
const (
	socksVersion = 0x05

	methodNoAuth      = 0x00
	methodUserPass    = 0x02
	methodNoAcceptable = 0xff

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess              = 0x00
	repServerFailure        = 0x01
	repConnNotAllowed       = 0x02
	repAddressTypeNotSupp   = 0x08
	repCommandNotSupp       = 0x07
)

// Inbound implements engine.Inbound for SOCKS5.
type Inbound struct {
	tag    string
	listen string

	// Optional username/password. Empty map = NO_AUTH only.
	users map[string]string

	mu       sync.Mutex
	tcpLn    net.Listener
	closed   bool
}

// New constructs a SOCKS5 Inbound bound to listen (e.g. ":1080").
//
// Pass an empty users map for unauthenticated SOCKS5 (typical for
// loopback-only deployments). For internet-facing deployments, supply
// at least one user — the SOCKS5 spec has no transport-level
// confidentiality and authenticated SOCKS5 is the bare minimum.
func New(tag, listen string, users map[string]string) *Inbound {
	if tag == "" {
		tag = "socks5"
	}
	return &Inbound{tag: tag, listen: listen, users: users}
}

func (i *Inbound) Tag() string { return i.tag }

func (i *Inbound) Start(ctx context.Context, h engine.InboundHandler) error {
	ln, err := net.Listen("tcp", i.listen)
	if err != nil {
		return fmt.Errorf("socks5: listen %s: %w", i.listen, err)
	}
	i.mu.Lock()
	i.tcpLn = ln
	i.mu.Unlock()
	log.Printf("[socks5] %q listening on %s", i.tag, ln.Addr())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("socks5: accept: %w", err)
		}
		go i.serveTCP(ctx, h, conn)
	}
}

func (i *Inbound) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	if i.tcpLn != nil {
		return i.tcpLn.Close()
	}
	return nil
}

// ----------------------------------------------------------------------
// TCP control connection
// ----------------------------------------------------------------------

func (i *Inbound) serveTCP(ctx context.Context, h engine.InboundHandler, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)

	if err := i.handshake(br, conn); err != nil {
		log.V("[socks5] handshake: %v", err)
		_ = conn.Close()
		return
	}

	cmd, dst, err := readRequest(br)
	if err != nil {
		log.V("[socks5] request: %v", err)
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch cmd {
	case cmdConnect:
		i.handleConnect(ctx, h, conn, dst)
	case cmdUDPAssociate:
		i.handleUDPAssociate(ctx, h, conn)
	default:
		_ = sendReply(conn, repCommandNotSupp)
		_ = conn.Close()
	}
}

// handshake performs the RFC 1928 method negotiation and (if needed)
// the RFC 1929 USERNAME/PASSWORD subnegotiation.
func (i *Inbound) handshake(br *bufio.Reader, conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if header[0] != socksVersion {
		return fmt.Errorf("bad version 0x%02x", header[0])
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	wantAuth := len(i.users) > 0
	chosen := byte(methodNoAcceptable)
	for _, m := range methods {
		if wantAuth && m == methodUserPass {
			chosen = methodUserPass
			break
		}
		if !wantAuth && m == methodNoAuth {
			chosen = methodNoAuth
			break
		}
	}
	if _, err := conn.Write([]byte{socksVersion, chosen}); err != nil {
		return fmt.Errorf("write method: %w", err)
	}
	if chosen == methodNoAcceptable {
		return errors.New("no acceptable auth method")
	}
	if chosen == methodUserPass {
		return i.subAuthUserPass(br, conn)
	}
	return nil
}

func (i *Inbound) subAuthUserPass(br *bufio.Reader, conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("bad subauth version 0x%02x", header[0])
	}
	user := make([]byte, header[1])
	if _, err := io.ReadFull(br, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(br, plen); err != nil {
		return err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(br, pass); err != nil {
		return err
	}
	want, ok := i.users[string(user)]
	if !ok || want != string(pass) {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("auth failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

// ----------------------------------------------------------------------
// CONNECT command
// ----------------------------------------------------------------------

func (i *Inbound) handleConnect(ctx context.Context, h engine.InboundHandler, conn net.Conn, dst engine.Endpoint) {
	if err := sendReply(conn, repSuccess); err != nil {
		_ = conn.Close()
		return
	}
	src := tcpRemoteEndpoint(conn)
	if err := h.HandleTCP(ctx, src, dst, conn); err != nil {
		log.V("[socks5] HandleTCP: %v", err)
		_ = conn.Close()
	}
}

// ----------------------------------------------------------------------
// UDP_ASSOCIATE command
// ----------------------------------------------------------------------
//
// RFC 1928 §6: client opens an unconnected UDP socket and sends
// SOCKS5 UDP packets to the BND address we report; we reply with the
// upstream answers, also wrapped in SOCKS5 UDP headers.
//
// In v2 we surface this to the engine as one engine.UDPConn per
// (client UDP src, dst) flow. Each new SOCKS5 UDP packet whose
// (atyp, addr, port) we have not seen creates a new UDP flow.

func (i *Inbound) handleUDPAssociate(ctx context.Context, h engine.InboundHandler, ctrl net.Conn) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		_ = sendReply(ctrl, repServerFailure)
		_ = ctrl.Close()
		return
	}
	bnd := udpConn.LocalAddr().(*net.UDPAddr)
	if err := sendReplyWithBind(ctrl, repSuccess, bnd); err != nil {
		_ = udpConn.Close()
		_ = ctrl.Close()
		return
	}

	// Hold the control connection open as the lifetime anchor.
	// When it dies, tear down everything.
	relay := newSocks5UDPRelay(udpConn)
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		_ = ctrl.Close()
		relay.close()
	}()

	relay.run(ctx, h)
	_ = udpConn.Close()
	_ = ctrl.Close()
}

// ----------------------------------------------------------------------
// Helpers — request/reply wire codecs
// ----------------------------------------------------------------------

func readRequest(br *bufio.Reader) (byte, engine.Endpoint, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return 0, engine.Endpoint{}, err
	}
	if header[0] != socksVersion || header[2] != 0x00 {
		return 0, engine.Endpoint{}, errors.New("bad request header")
	}
	cmd := header[1]
	atyp := header[3]
	dst, err := readAddr(br, atyp)
	if err != nil {
		return 0, engine.Endpoint{}, err
	}
	return cmd, dst, nil
}

func readAddr(br *bufio.Reader, atyp byte) (engine.Endpoint, error) {
	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return engine.Endpoint{}, err
		}
		var port [2]byte
		if _, err := io.ReadFull(br, port[:]); err != nil {
			return engine.Endpoint{}, err
		}
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}),
			binary.BigEndian.Uint16(port[:]))
		return engine.Endpoint{Addr: addr, Port: addr.Port()}, nil
	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return engine.Endpoint{}, err
		}
		var port [2]byte
		if _, err := io.ReadFull(br, port[:]); err != nil {
			return engine.Endpoint{}, err
		}
		var arr [16]byte
		copy(arr[:], ip)
		addr := netip.AddrPortFrom(netip.AddrFrom16(arr), binary.BigEndian.Uint16(port[:]))
		return engine.Endpoint{Addr: addr, Port: addr.Port()}, nil
	case atypDomain:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(br, ln); err != nil {
			return engine.Endpoint{}, err
		}
		host := make([]byte, ln[0])
		if _, err := io.ReadFull(br, host); err != nil {
			return engine.Endpoint{}, err
		}
		var port [2]byte
		if _, err := io.ReadFull(br, port[:]); err != nil {
			return engine.Endpoint{}, err
		}
		return engine.Endpoint{Domain: string(host), Port: binary.BigEndian.Uint16(port[:])}, nil
	default:
		return engine.Endpoint{}, fmt.Errorf("unsupported atyp 0x%02x", atyp)
	}
}

func sendReply(conn net.Conn, rep byte) error {
	// REP + RSV + ATYP=IPv4 + 0.0.0.0:0
	_, err := conn.Write([]byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func sendReplyWithBind(conn net.Conn, rep byte, bnd *net.UDPAddr) error {
	out := []byte{socksVersion, rep, 0x00}
	ip4 := bnd.IP.To4()
	if ip4 != nil {
		out = append(out, atypIPv4)
		out = append(out, ip4...)
	} else {
		out = append(out, atypIPv6)
		out = append(out, bnd.IP.To16()...)
	}
	out = append(out, byte(bnd.Port>>8), byte(bnd.Port))
	_, err := conn.Write(out)
	return err
}

func tcpRemoteEndpoint(c net.Conn) engine.Endpoint {
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return engine.Endpoint{}
	}
	addr, ok := netip.AddrFromSlice(ra.IP)
	if !ok {
		return engine.Endpoint{}
	}
	ap := netip.AddrPortFrom(addr.Unmap(), uint16(ra.Port))
	return engine.Endpoint{Addr: ap, Port: ap.Port()}
}

// portString satisfies the unused-warning hat; kept for symmetry with
// callers that may want it later.
var _ = strconv.Itoa
