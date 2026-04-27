// Package http is an HTTP proxy Inbound supporting:
//
//   - HTTP CONNECT (RFC 7231 §4.3.6) — for HTTPS or any TCP tunnel
//   - HTTP forward proxy with absolute-form request URI — for plain
//     HTTP traffic (rare in 2026 but still used by some test rigs)
//
// Both modes hand the resulting flow to the engine via HandleTCP.
package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"ewp-core/engine"
	"ewp-core/log"
)

type Inbound struct {
	tag    string
	listen string

	mu     sync.Mutex
	ln     net.Listener
	closed bool
}

func New(tag, listen string) *Inbound {
	if tag == "" {
		tag = "http"
	}
	return &Inbound{tag: tag, listen: listen}
}

func (i *Inbound) Tag() string { return i.tag }

func (i *Inbound) Start(ctx context.Context, h engine.InboundHandler) error {
	ln, err := net.Listen("tcp", i.listen)
	if err != nil {
		return fmt.Errorf("http: listen %s: %w", i.listen, err)
	}
	i.mu.Lock()
	i.ln = ln
	i.mu.Unlock()
	log.Printf("[http] %q listening on %s", i.tag, ln.Addr())

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
			return fmt.Errorf("http: accept: %w", err)
		}
		go i.serve(ctx, h, conn)
	}
}

func (i *Inbound) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	if i.ln != nil {
		return i.ln.Close()
	}
	return nil
}

// serve handles one client connection. We DO NOT use net/http.Server
// because we need byte-stream control after CONNECT — net/http hijack
// would work but adds boilerplate for no gain here.
func (i *Inbound) serve(ctx context.Context, h engine.InboundHandler, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		i.handleConnect(ctx, h, conn, req)
		return
	}
	i.handleForward(ctx, h, conn, br, req)
}

func (i *Inbound) handleConnect(ctx context.Context, h engine.InboundHandler, conn net.Conn, req *http.Request) {
	host, port, err := splitHostPort(req.URL.Host, "443")
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "bad CONNECT target")
		_ = conn.Close()
		return
	}
	dst := buildEndpoint(host, port)

	// CONNECT response BEFORE handing to the engine; subsequent bytes
	// are the tunnel.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = conn.Close()
		return
	}
	src := tcpRemoteEndpoint(conn)
	if err := h.HandleTCP(ctx, src, dst, conn); err != nil {
		log.V("[http] HandleTCP CONNECT: %v", err)
		_ = conn.Close()
	}
}

// handleForward implements the rare absolute-form HTTP forward proxy
// path. We open the connection through the engine, forward the
// request, then turn into a byte pipe.
//
// Limitations: keep-alive across multiple absolute-form requests on
// one connection is NOT supported (we close after the first
// response). Real-world usage of plaintext HTTP forward proxies is
// near-zero in 2026; this branch exists for diagnostic tooling.
func (i *Inbound) handleForward(ctx context.Context, h engine.InboundHandler, conn net.Conn, br *bufio.Reader, req *http.Request) {
	if req.URL == nil || req.URL.Host == "" {
		writeHTTPError(conn, http.StatusBadRequest, "absolute-form URI required")
		_ = conn.Close()
		return
	}
	host, port, err := splitHostPort(req.URL.Host, "80")
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "bad target")
		_ = conn.Close()
		return
	}
	dst := buildEndpoint(host, port)
	src := tcpRemoteEndpoint(conn)

	// We can't reuse the existing conn directly because the engine
	// dispatch is asynchronous and we still need to write the request
	// onto the upstream side. Instead we wrap conn into a "pre-buffered"
	// reader that surfaces the request bytes first, then live data.
	if err := req.Write(io.Discard); err != nil {
		// Sanity-check serialisation
		writeHTTPError(conn, http.StatusInternalServerError, "request encode")
		_ = conn.Close()
		return
	}

	// Strip hop-by-hop headers per RFC 7230.
	req.RequestURI = req.URL.RequestURI()
	req.URL.Host = ""
	req.URL.Scheme = ""
	for _, hop := range []string{"Proxy-Connection", "Proxy-Authorization"} {
		req.Header.Del(hop)
	}

	upstreamReq := &requestPrefixedConn{br: br, conn: conn, prefix: nil}
	pre, err := serializeRequest(req)
	if err != nil {
		writeHTTPError(conn, http.StatusInternalServerError, "serialize")
		_ = conn.Close()
		return
	}
	upstreamReq.prefix = pre

	if err := h.HandleTCP(ctx, src, dst, upstreamReq); err != nil {
		log.V("[http] HandleTCP forward: %v", err)
		_ = conn.Close()
	}
}

// ----------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------

func splitHostPort(hostPort, defaultPort string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		port = defaultPort
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("port: %w", err)
	}
	return host, uint16(pn), nil
}

func buildEndpoint(host string, port uint16) engine.Endpoint {
	if ip, err := netip.ParseAddr(host); err == nil {
		return engine.Endpoint{Addr: netip.AddrPortFrom(ip, port), Port: port}
	}
	return engine.Endpoint{Domain: host, Port: port}
}

func writeHTTPError(c net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	_, _ = c.Write([]byte(resp))
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

// requestPrefixedConn wraps a net.Conn so that the first reads return
// `prefix` (the serialised request) before falling through to the
// underlying buffered reader.
type requestPrefixedConn struct {
	prefix []byte
	br     *bufio.Reader
	conn   net.Conn
	mu     sync.Mutex
}

func (c *requestPrefixedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.br.Read(p)
}

func (c *requestPrefixedConn) Write(p []byte) (int, error) { return c.conn.Write(p) }
func (c *requestPrefixedConn) Close() error                { return c.conn.Close() }

func serializeRequest(req *http.Request) ([]byte, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	buf := &writableBuffer{}
	if err := req.Write(buf); err != nil {
		return nil, err
	}
	return buf.b, nil
}

type writableBuffer struct{ b []byte }

func (w *writableBuffer) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

// Compile-time check.
var _ engine.TCPConn = (*requestPrefixedConn)(nil)
