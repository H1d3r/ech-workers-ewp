package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

var _ BootstrapTransport = (*DoQTransport)(nil)

// DoQTransport implements DNS over QUIC (RFC 9250)
type DoQTransport struct {
	server     string // e.g., "dns.alidns.com:853"
	tlsConfig  *tls.Config
	quicConfig *quic.Config
}

// NewDoQTransport creates a new DoQ transport
func NewDoQTransport(server string) (*DoQTransport, error) {
	// Parse server address
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// No port specified, add default DoQ port 853
		host = server
		port = "853"
		server = net.JoinHostPort(host, port)
	}

	return &DoQTransport{
		server: server,
		tlsConfig: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"doq"}, // ALPN for DoQ (RFC 9250)
		},
		quicConfig: &quic.Config{
			MaxIdleTimeout:  10 * time.Second,
			KeepAlivePeriod: 3 * time.Second,
		},
	}, nil
}

// Query performs a DNS query via DoQ
func (t *DoQTransport) Query(ctx context.Context, domain string, qtype uint16) ([]net.IP, error) {
	// Build DNS query
	dnsQuery := BuildQuery(domain, qtype)

	// Apply timeout to context
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Establish QUIC connection (server should be IP:port to avoid DNS lookup)
	conn, err := quic.DialAddr(ctx, t.server, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}
	defer conn.CloseWithError(0, "")

	// Open bidirectional stream for DNS query
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Set deadline for stream operations
	deadline, ok := ctx.Deadline()
	if ok {
		stream.SetDeadline(deadline)
	}

	// DoQ uses length-prefixed DNS messages (RFC 9250 Section 4.2.1)
	// Write length prefix (2 bytes, big endian)
	if err := binary.Write(stream, binary.BigEndian, uint16(len(dnsQuery))); err != nil {
		return nil, fmt.Errorf("failed to write length: %w", err)
	}

	// Write DNS message
	if _, err := stream.Write(dnsQuery); err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}

	// Read length prefix of response
	var responseLen uint16
	if err := binary.Read(stream, binary.BigEndian, &responseLen); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	if responseLen == 0 || responseLen > 4096 {
		return nil, fmt.Errorf("invalid response length: %d", responseLen)
	}

	// Read DNS response
	response := make([]byte, responseLen)
	if _, err := io.ReadFull(stream, response); err != nil {
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
func (t *DoQTransport) Type() string {
	return "DoQ"
}

// Server returns the server address
func (t *DoQTransport) Server() string {
	return t.server
}

// Close closes the transport and releases resources
func (t *DoQTransport) Close() error {
	// DoQ doesn't maintain persistent connections in this implementation
	return nil
}
