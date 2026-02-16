package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

var _ BootstrapTransport = (*DoTTransport)(nil)

// DoTTransport implements DNS over TLS (RFC 7858)
type DoTTransport struct {
	server    string // e.g., "dns.alidns.com:853"
	tlsConfig *tls.Config
}

// NewDoTTransport creates a new DoT transport
func NewDoTTransport(server string) (*DoTTransport, error) {
	// Parse server address
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// No port specified, add default DoT port 853
		host = server
		port = "853"
		server = net.JoinHostPort(host, port)
	}

	return &DoTTransport{
		server: server,
		tlsConfig: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"dot"}, // ALPN for DoT (optional)
		},
	}, nil
}

// Query performs a DNS query via DoT
func (t *DoTTransport) Query(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	// Build DNS query
	dnsQuery := BuildQuery(domain, qtype)

	// Connect with timeout
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Establish TLS connection
	conn, err := tls.DialWithDialer(dialer, "tcp", t.server, t.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	// Set deadline for entire operation
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// DoT uses length-prefixed DNS messages (RFC 7858 Section 3.3)
	// Write length prefix (2 bytes, big endian)
	if err := binary.Write(conn, binary.BigEndian, uint16(len(dnsQuery))); err != nil {
		return nil, fmt.Errorf("failed to write length: %w", err)
	}

	// Write DNS message
	if _, err := conn.Write(dnsQuery); err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}

	// Read length prefix of response
	var responseLen uint16
	if err := binary.Read(conn, binary.BigEndian, &responseLen); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	if responseLen == 0 || responseLen > 4096 {
		return nil, fmt.Errorf("invalid response length: %d", responseLen)
	}

	// Read DNS response
	response := make([]byte, responseLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse DNS response
	ips, err := parseDNSResponse(response, qtype)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS response: %w", err)
	}

	return ips, nil
}

// Type returns the transport type
func (t *DoTTransport) Type() string {
	return "DoT"
}

// Server returns the server address
func (t *DoTTransport) Server() string {
	return t.server
}

// Close closes the transport and releases resources
func (t *DoTTransport) Close() error {
	// DoT doesn't maintain persistent connections in this implementation
	return nil
}
