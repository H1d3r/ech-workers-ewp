package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"ewp-core/log"
	"ewp-core/transport"
)

var _ TunnelDNSTransport = (*TunnelDoHTransport)(nil)

// TunnelDoHTransport performs DoH queries through a proxy tunnel
// This ensures all DNS queries are encrypted and routed through the proxy
type TunnelDoHTransport struct {
	serverURL string
	timeout   time.Duration
	transport transport.Transport
}

// NewTunnelDoHTransport creates a new DoH transport that uses proxy tunnel
func NewTunnelDoHTransport(dohServer string, trans transport.Transport) *TunnelDoHTransport {
	if dohServer == "" {
		dohServer = "https://dns.google/dns-query"
	}

	return &TunnelDoHTransport{
		serverURL: dohServer,
		timeout:   10 * time.Second,
		transport: trans,
	}
}

// Legacy compatibility: TunnelDoHClient
type TunnelDoHClient = TunnelDoHTransport

// NewTunnelDoHClient creates a new DoH client (legacy compatibility)
func NewTunnelDoHClient(dohServer string, trans transport.Transport) *TunnelDoHClient {
	return NewTunnelDoHTransport(dohServer, trans)
}

// QueryRaw performs a raw DNS query through the proxy tunnel using HTTP/2 POST (RFC 8484)
func (c *TunnelDoHTransport) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	// Establish tunnel connection
	conn, err := c.transport.Dial()
	if err != nil {
		return nil, fmt.Errorf("failed to dial tunnel: %w", err)
	}
	defer conn.Close()

	// Parse DoH server URL
	u, err := url.Parse(c.serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	// Determine target for tunnel
	targetHost := u.Hostname()
	targetPort := u.Port()
	if targetPort == "" {
		targetPort = "443"
	}
	target := net.JoinHostPort(targetHost, targetPort)

	// Connect tunnel to DoH server
	if err := conn.Connect(target, nil); err != nil {
		return nil, fmt.Errorf("tunnel connect failed: %w", err)
	}

	// Build HTTP POST request (RFC 8484 recommends POST over GET)
	httpReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		u.Path, u.Hostname(), len(dnsQuery))

	// Send HTTP headers and DNS query body
	if err := conn.Write([]byte(httpReq)); err != nil {
		return nil, fmt.Errorf("failed to send request headers: %w", err)
	}
	if err := conn.Write(dnsQuery); err != nil {
		return nil, fmt.Errorf("failed to send request body: %w", err)
	}

	// Read HTTP response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if n == 0 {
		return nil, fmt.Errorf("empty response")
	}

	// Parse HTTP response
	dnsResponse, err := c.parseHTTPResponse(response[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTTP response: %w", err)
	}

	log.V("[TunnelDoH] Query successful: %d bytes", len(dnsResponse))
	return dnsResponse, nil
}

// Type returns the transport type
func (c *TunnelDoHTransport) Type() string {
	return "Tunnel-DoH"
}

// Server returns the server address
func (c *TunnelDoHTransport) Server() string {
	return c.serverURL
}

// Close closes the transport and releases resources
func (c *TunnelDoHTransport) Close() error {
	// No persistent resources to close
	return nil
}

// parseHTTPResponse extracts DNS message from HTTP response
func (c *TunnelDoHTransport) parseHTTPResponse(httpResponse []byte) ([]byte, error) {
	// Find end of headers (\r\n\r\n)
	headerEnd := bytes.Index(httpResponse, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, fmt.Errorf("invalid HTTP response: no header end")
	}

	// Check status code
	statusLine := bytes.SplitN(httpResponse[:headerEnd], []byte("\r\n"), 2)[0]
	if !bytes.Contains(statusLine, []byte("200")) {
		return nil, fmt.Errorf("HTTP error: %s", statusLine)
	}

	// Extract body (DNS message)
	body := httpResponse[headerEnd+4:]
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	return body, nil
}

// Query performs a DoH query for domain and record type (legacy compatibility)
func (c *TunnelDoHTransport) Query(domain string, qtype uint16) ([]byte, error) {
	dnsQuery := BuildQuery(domain, qtype)
	return c.QueryRaw(context.Background(), dnsQuery)
}

// QueryRawLegacy performs a raw DNS query (legacy compatibility, no context)
func (c *TunnelDoHTransport) QueryRawLegacy(dnsQuery []byte) ([]byte, error) {
	return c.QueryRaw(context.Background(), dnsQuery)
}
