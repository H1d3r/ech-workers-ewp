package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ewp-core/constant"
	"ewp-core/log"

	"golang.org/x/net/http2"
)

// Client represents a DoH (DNS over HTTPS) client
type Client struct {
	ServerURL  string
	Timeout    time.Duration
	httpClient *http.Client
}

// NewClient creates a new DoH client that works without DNS resolution
func NewClient(serverURL string) *Client {
	return NewClientWithDialer(serverURL, nil)
}

// NewClientWithDialer creates a new DoH client using the provided dialer for TCP connections.
// Pass a bypass dialer (e.g. bound to a physical interface) to prevent the DoH request
// from being intercepted by a TUN device. Pass nil to use the default dialer.
func NewClientWithDialer(serverURL string, dialer *net.Dialer) *Client {
	if !strings.HasPrefix(serverURL, "https://") && !strings.HasPrefix(serverURL, "http://") {
		serverURL = "https://" + serverURL
	}

	if dialer == nil {
		dialer = &net.Dialer{Timeout: 5 * time.Second}
	}

	// Parse URL to get server name for SNI
	u, err := url.Parse(serverURL)
	if err != nil {
		log.Printf("[DoH Client] Invalid URL %s: %v", serverURL, err)
		return &Client{
			ServerURL: serverURL,
			Timeout:   10 * time.Second,
			httpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
		}
	}

	serverName := u.Hostname()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		ServerName: serverName,
	}

	d := dialer
	transport := &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
		AllowHTTP:          false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			log.V("[DoH Client] Dialing %s %s (SNI: %s)", network, addr, cfg.ServerName)

			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				log.Printf("[DoH Client] TCP dial failed: %v", err)
				return nil, err
			}

			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				log.Printf("[DoH Client] TLS handshake failed: %v", err)
				return nil, err
			}

			log.V("[DoH Client] TLS connection established to %s", addr)
			return tlsConn, nil
		},
	}

	return &Client{
		ServerURL: serverURL,
		Timeout:   10 * time.Second,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// QueryHTTPS queries HTTPS record for ECH configuration
func (c *Client) QueryHTTPS(domain string) (string, error) {
	return c.Query(domain, constant.TypeHTTPS)
}

// Query performs a DoH query using POST method (RFC 8484)
func (c *Client) Query(domain string, qtype uint16) (string, error) {
	log.Printf("[DoH Client] Querying %s (type %d) via %s", domain, qtype, c.ServerURL)

	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid DoH URL: %w", err)
	}

	// Build DNS query
	dnsQuery := BuildQuery(domain, qtype)

	// Create HTTP POST request with DNS query as body
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(dnsQuery))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Send request using configured HTTP client
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Parse DNS response
	echBase64, err := ParseResponse(body)
	if err != nil {
		return "", fmt.Errorf("failed to parse DNS response: %w", err)
	}

	if echBase64 == "" {
		log.Printf("[DoH Client] No ECH parameter found for %s", domain)
		return "", fmt.Errorf("no ECH parameter found")
	}

	log.Printf("[DoH Client] Successfully retrieved ECH config for %s (%d bytes)", domain, len(echBase64))
	return echBase64, nil
}

// QueryRaw performs a raw DoH query using POST method (RFC 8484)
func (c *Client) QueryRaw(dnsQuery []byte) ([]byte, error) {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	// Create HTTP POST request with raw DNS query as body
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Send request using configured HTTP client
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// MultiClient represents a DoH client that races multiple servers.
// P0-12: Provides redundancy and automatic failover. The first server to
// respond successfully wins; others are cancelled. This prevents a single
// slow/blocked DoH server from degrading the entire bootstrap process.
type MultiClient struct {
	clients []*Client
	timeout time.Duration
}

// NewMultiClient creates a DoH client that races multiple servers.
// serverURLs should contain 2+ DoH endpoints for redundancy.
// Pass a bypass dialer to prevent DoH requests from being intercepted by TUN.
func NewMultiClient(serverURLs []string, dialer *net.Dialer) *MultiClient {
	if len(serverURLs) == 0 {
		serverURLs = constant.DefaultDNSServers
	}
	
	clients := make([]*Client, 0, len(serverURLs))
	for _, url := range serverURLs {
		clients = append(clients, NewClientWithDialer(url, dialer))
	}
	
	return &MultiClient{
		clients: clients,
		timeout: 10 * time.Second,
	}
}

// QueryHTTPS queries HTTPS record for ECH configuration from multiple servers.
// Returns the first successful response; cancels remaining requests.
func (mc *MultiClient) QueryHTTPS(domain string) (string, error) {
	return mc.Query(domain, constant.TypeHTTPS)
}

// Query performs a DoH query racing all configured servers.
// P0-12: First successful response wins; failures are logged but don't block.
// Returns error only if ALL servers fail.
func (mc *MultiClient) Query(domain string, qtype uint16) (string, error) {
	if len(mc.clients) == 0 {
		return "", fmt.Errorf("no DoH servers configured")
	}
	
	// Fast path: single server
	if len(mc.clients) == 1 {
		return mc.clients[0].Query(domain, qtype)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), mc.timeout)
	defer cancel()
	
	type result struct {
		data string
		err  error
		from string
	}
	
	resultCh := make(chan result, len(mc.clients))
	var wg sync.WaitGroup
	
	// Launch parallel queries
	for _, client := range mc.clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			
			// Check if context already cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			data, err := c.Query(domain, qtype)
			select {
			case resultCh <- result{data: data, err: err, from: c.ServerURL}:
			case <-ctx.Done():
			}
		}(client)
	}
	
	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultCh)
	}()
	
	// Collect results
	var lastErr error
	successCount := 0
	failCount := 0
	
	for res := range resultCh {
		if res.err == nil {
			successCount++
			log.Printf("[DoH MultiClient] ✅ %s responded first for %s", res.from, domain)
			// Cancel remaining requests
			cancel()
			return res.data, nil
		}
		failCount++
		lastErr = res.err
		log.V("[DoH MultiClient] ❌ %s failed: %v", res.from, res.err)
	}
	
	// All servers failed
	return "", fmt.Errorf("all %d DoH servers failed (last error: %w)", failCount, lastErr)
}

// QueryRaw performs a raw DoH query racing all configured servers.
func (mc *MultiClient) QueryRaw(dnsQuery []byte) ([]byte, error) {
	if len(mc.clients) == 0 {
		return nil, fmt.Errorf("no DoH servers configured")
	}
	
	// Fast path: single server
	if len(mc.clients) == 1 {
		return mc.clients[0].QueryRaw(dnsQuery)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), mc.timeout)
	defer cancel()
	
	type result struct {
		data []byte
		err  error
		from string
	}
	
	resultCh := make(chan result, len(mc.clients))
	var wg sync.WaitGroup
	
	// Launch parallel queries
	for _, client := range mc.clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			data, err := c.QueryRaw(dnsQuery)
			select {
			case resultCh <- result{data: data, err: err, from: c.ServerURL}:
			case <-ctx.Done():
			}
		}(client)
	}
	
	go func() {
		wg.Wait()
		close(resultCh)
	}()
	
	// Return first success
	var lastErr error
	for res := range resultCh {
		if res.err == nil {
			cancel()
			return res.data, nil
		}
		lastErr = res.err
	}
	
	return nil, fmt.Errorf("all DoH servers failed: %w", lastErr)
}
