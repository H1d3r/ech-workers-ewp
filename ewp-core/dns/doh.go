package dns

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ewp-core/constant"
)

// Client represents a DoH (DNS over HTTPS) client
type Client struct {
	ServerURL string
	Timeout   time.Duration
}

// NewClient creates a new DoH client
func NewClient(serverURL string) *Client {
	if !strings.HasPrefix(serverURL, "https://") && !strings.HasPrefix(serverURL, "http://") {
		serverURL = "https://" + serverURL
	}

	return &Client{
		ServerURL: serverURL,
		Timeout:   10 * time.Second,
	}
}

// QueryHTTPS queries HTTPS record for ECH configuration
func (c *Client) QueryHTTPS(domain string) (string, error) {
	return c.Query(domain, constant.TypeHTTPS)
}

// Query performs a DoH query using POST method (RFC 8484)
func (c *Client) Query(domain string, qtype uint16) (string, error) {
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

	// Send request
	client := &http.Client{Timeout: c.Timeout}
	resp, err := client.Do(req)
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
		return "", fmt.Errorf("no ECH parameter found")
	}

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

	client := &http.Client{Timeout: c.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned error: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
