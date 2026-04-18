package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"ewp-core/log"

	"golang.org/x/net/http2"
)

// BypassResolver resolves hostnames using a DNS connection that bypasses the TUN device.
// When multiple IPs are returned, all are probed in parallel and the one with the lowest
// TCP handshake latency is returned (optimal CDN edge-node selection).
// Results are cached to avoid port exhaustion under high-concurrency TUN traffic.
// P1-15: Supports both DoH (encrypted, recommended) and plain DNS (legacy).
type BypassResolver struct {
	resolver  *net.Resolver // nil in DoH mode
	tcpDialer *net.Dialer

	// P1-15: DoH support
	dohServer  string   // Single DoH server URL
	dohServers []string // Multi-DoH racing servers
	dohDialer  *net.Dialer

	// DNS result cache
	mu       sync.Mutex
	cache    map[string]*dnsEntry
	cacheTTL time.Duration // P1-27: Extended to 1h to reduce probe frequency
}

type dnsEntry struct {
	ip      string
	expires time.Time
}

// NewBypassResolver creates a resolver whose DNS queries use the bypass TCP dialer,
// ensuring DNS traffic does not loop through the TUN device.
// P1-15: dnsServer can be:
//   - DoH URL: "https://223.5.5.5/dns-query" (recommended, encrypted)
//   - Plain DNS: "8.8.8.8:53" (legacy, plaintext - exposes proxy domains to ISP)
//   - Empty: defaults to multi-DoH racing (Aliyun + DNSPod)
// dnsServers: optional list of DoH servers for multi-server racing (overrides dnsServer)
func NewBypassResolver(cfg *BypassConfig, dnsServer string, dnsServers []string) *BypassResolver {
	// Priority: dnsServers array > dnsServer string > default
	if len(dnsServers) > 1 {
		// Multi-DoH racing mode with custom servers
		log.Info("[BypassResolver] Using custom multi-DoH racing: %v", dnsServers)
		
		return &BypassResolver{
			resolver:   nil, // DoH mode
			tcpDialer:  cfg.TCPDialer,
			cache:      make(map[string]*dnsEntry),
			cacheTTL:   60 * time.Minute,
			dohServer:  "", // Multi-DoH mode
			dohDialer:  cfg.TCPDialer,
			dohServers: dnsServers,
		}
	}
	
	// Default to multi-DoH racing with China-friendly servers
	// Uses Aliyun DNS (223.5.5.5, 223.6.6.6) and DNSPod
	// These servers work well in China and avoid 1.1.1.1 blocking issues
	if dnsServer == "" && len(dnsServers) == 0 {
		dohServers := []string{
			"https://223.5.5.5/dns-query",      // Aliyun DNS (primary)
			"https://223.6.6.6/dns-query",      // Aliyun DNS (secondary)
			"https://doh.pub/dns-query",        // DNSPod (Tencent)
		}
		
		log.Info("[BypassResolver] Using default multi-DoH racing: %v", dohServers)
		
		return &BypassResolver{
			resolver:   nil, // DoH mode
			tcpDialer:  cfg.TCPDialer,
			cache:      make(map[string]*dnsEntry),
			cacheTTL:   60 * time.Minute,
			dohServer:  "", // Multi-DoH mode
			dohDialer:  cfg.TCPDialer,
			dohServers: dohServers,
		}
	}
	
	// Single DoH server mode
	if isDoHURL(dnsServer) {
		log.Info("[BypassResolver] Using single DoH: %s", dnsServer)
		
		return &BypassResolver{
			resolver:  nil, // DoH mode
			tcpDialer: cfg.TCPDialer,
			cache:     make(map[string]*dnsEntry),
			cacheTTL:  60 * time.Minute,
			dohServer: dnsServer,
			dohDialer: cfg.TCPDialer,
		}
	}
	
	// Legacy plain DNS mode
	log.Info("[BypassResolver] Using plain DNS: %s", dnsServer)
	
	server := dnsServer
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return cfg.TCPDialer.DialContext(ctx, "tcp", server)
		},
	}
	return &BypassResolver{
		resolver:  r,
		tcpDialer: cfg.TCPDialer,
		cache:     make(map[string]*dnsEntry),
		cacheTTL:  60 * time.Minute,
	}
}

// isDoHURL checks if the DNS server is a DoH URL
func isDoHURL(server string) bool {
	return len(server) > 8 && (server[:8] == "https://" || server[:7] == "http://")
}

// ResolveBestIP resolves host and returns the IP with the lowest TCP latency on port.
// Results are cached for cacheTTL to prevent port exhaustion in TUN mode.
// P1-15: Uses DoH if configured, otherwise falls back to plain DNS.
func (r *BypassResolver) ResolveBestIP(host, port string) (string, error) {
	cacheKey := host + ":" + port

	// Fast path: check cache
	r.mu.Lock()
	if entry, ok := r.cache[cacheKey]; ok && time.Now().Before(entry.expires) {
		ip := entry.ip
		r.mu.Unlock()
		return ip, nil
	}
	r.mu.Unlock()

	// Slow path: resolve and probe
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var addrs []string
	var err error
	
	// Use DoH if configured (single or multi-server racing)
	if r.dohServer != "" || len(r.dohServers) > 0 {
		addrs, err = r.resolveViaDoH(ctx, host)
	} else {
		addrs, err = r.resolver.LookupHost(ctx, host)
	}
	
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("bypass DNS resolve %s: %w", host, err)
	}

	var bestIP string
	if len(addrs) == 1 {
		bestIP = addrs[0]
	} else {
		bestIP = r.probeBestIP(ctx, addrs, port)
	}

	// Store in cache
	r.mu.Lock()
	r.cache[cacheKey] = &dnsEntry{ip: bestIP, expires: time.Now().Add(r.cacheTTL)}
	r.mu.Unlock()

	return bestIP, nil
}

// resolveViaDoH performs DNS resolution using DoH (DNS over HTTPS).
// P1-15: This prevents ISP from seeing proxy server domain names.
// Supports both single-server and multi-server racing modes.
func (r *BypassResolver) resolveViaDoH(ctx context.Context, host string) ([]string, error) {
	// Multi-DoH racing mode (default)
	if len(r.dohServers) > 0 {
		return r.resolveViaMultiDoH(ctx, host)
	}
	
	// Single DoH server mode
	if r.dohServer != "" {
		return r.resolveViaSingleDoH(ctx, host)
	}
	
	return nil, fmt.Errorf("no DoH server configured")
}

// resolveViaSingleDoH resolves using a single DoH server
func (r *BypassResolver) resolveViaSingleDoH(ctx context.Context, host string) ([]string, error) {
	// Build DNS query for A record (Type 1 = IPv4)
	query := buildDNSQuery(host, 1)
	
	// Send DoH request
	resp, err := r.sendDoHRequest(ctx, r.dohServer, query)
	if err != nil {
		return nil, fmt.Errorf("DoH query failed: %w", err)
	}
	
	// Parse response
	addrs, err := parseDNSAddressRecords(resp)
	if err != nil {
		return nil, fmt.Errorf("parse DNS response failed: %w", err)
	}
	
	log.V("[BypassResolver] Resolved %s via DoH: %v", host, addrs)
	return addrs, nil
}

// resolveViaMultiDoH resolves using multiple DoH servers in racing mode
// Similar to ECH config fetching (P0-12), first successful response wins
func (r *BypassResolver) resolveViaMultiDoH(ctx context.Context, host string) ([]string, error) {
	type result struct {
		addrs []string
		err   error
		from  string
	}
	
	resultCh := make(chan result, len(r.dohServers))
	var wg sync.WaitGroup
	
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	// Build DNS query once
	query := buildDNSQuery(host, 1) // Type 1 = A record (IPv4)
	
	// Launch parallel queries to all DoH servers
	for _, serverURL := range r.dohServers {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			
			select {
			case <-queryCtx.Done():
				return
			default:
			}
			
			// Send DoH request
			resp, err := r.sendDoHRequest(queryCtx, url, query)
			if err != nil {
				select {
				case resultCh <- result{err: fmt.Errorf("DoH query failed: %w", err), from: url}:
				case <-queryCtx.Done():
				}
				return
			}
			
			// Parse response
			addrs, err := parseDNSAddressRecords(resp)
			select {
			case resultCh <- result{addrs: addrs, err: err, from: url}:
			case <-queryCtx.Done():
			}
		}(serverURL)
	}
	
	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultCh)
	}()
	
	// Return first successful result
	var lastErr error
	for res := range resultCh {
		if res.err == nil && len(res.addrs) > 0 {
			log.Printf("[BypassResolver] ✅ %s responded first for %s: %v", res.from, host, res.addrs)
			cancel() // Cancel remaining queries
			return res.addrs, nil
		}
		if res.err != nil {
			lastErr = res.err
			log.V("[BypassResolver] ❌ %s failed: %v", res.from, res.err)
		}
	}
	
	// All servers failed
	if lastErr != nil {
		return nil, fmt.Errorf("all DoH servers failed: %w", lastErr)
	}
	return nil, fmt.Errorf("all DoH servers returned empty results")
}

// sendDoHRequest sends a DNS query over HTTPS
func (r *BypassResolver) sendDoHRequest(ctx context.Context, serverURL string, query []byte) ([]byte, error) {
	// Create HTTP/2 client with bypass dialer
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}
	
	transport := &http2.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: false,
		AllowHTTP:          false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := r.dohDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			
			return tlsConn, nil
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	
	// Create HTTP POST request
	req, err := http.NewRequestWithContext(ctx, "POST", serverURL, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server error: %d", resp.StatusCode)
	}
	
	return io.ReadAll(resp.Body)
}

// buildDNSQuery builds a DNS query packet
func buildDNSQuery(domain string, qtype uint16) []byte {
	buf := make([]byte, 0, 512)
	
	// Transaction ID (random)
	txid := make([]byte, 2)
	rand.Read(txid)
	buf = append(buf, txid...)
	
	// Flags: standard query, recursion desired
	buf = append(buf, 0x01, 0x00)
	
	// Questions: 1
	buf = append(buf, 0x00, 0x01)
	
	// Answer RRs: 0
	buf = append(buf, 0x00, 0x00)
	
	// Authority RRs: 0
	buf = append(buf, 0x00, 0x00)
	
	// Additional RRs: 0
	buf = append(buf, 0x00, 0x00)
	
	// Question section
	// Domain name (labels)
	labels := []byte(domain)
	start := 0
	for i := 0; i < len(labels); i++ {
		if labels[i] == '.' || i == len(labels)-1 {
			end := i
			if i == len(labels)-1 && labels[i] != '.' {
				end = i + 1
			}
			length := end - start
			buf = append(buf, byte(length))
			buf = append(buf, labels[start:end]...)
			start = i + 1
		}
	}
	buf = append(buf, 0x00) // End of domain name
	
	// Query type
	buf = append(buf, byte(qtype>>8), byte(qtype))
	
	// Query class (IN = 1)
	buf = append(buf, 0x00, 0x01)
	
	return buf
}

// parseDNSAddressRecords parses A and AAAA records from DNS response
func parseDNSAddressRecords(response []byte) ([]string, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("response too short")
	}
	
	// Parse DNS header
	answerCount := int(response[6])<<8 | int(response[7])
	if answerCount == 0 {
		return nil, fmt.Errorf("no answers")
	}
	
	offset := 12
	
	// Skip question section
	offset, err := skipDNSName(response, offset)
	if err != nil {
		return nil, fmt.Errorf("skip question: %w", err)
	}
	if offset+4 > len(response) {
		return nil, fmt.Errorf("truncated question")
	}
	offset += 4 // qtype + qclass
	
	var addresses []string
	
	// Parse answer section
	for i := 0; i < answerCount && offset < len(response); i++ {
		// Skip name
		offset, err = skipDNSName(response, offset)
		if err != nil {
			return nil, fmt.Errorf("skip answer name: %w", err)
		}
		
		if offset+10 > len(response) {
			return nil, fmt.Errorf("truncated answer")
		}
		
		recordType := uint16(response[offset])<<8 | uint16(response[offset+1])
		dataLen := int(response[offset+8])<<8 | int(response[offset+9])
		offset += 10
		
		if offset+dataLen > len(response) {
			return nil, fmt.Errorf("truncated data")
		}
		
		// Type A (1) - IPv4
		if recordType == 1 && dataLen == 4 {
			ip := fmt.Sprintf("%d.%d.%d.%d",
				response[offset], response[offset+1],
				response[offset+2], response[offset+3])
			addresses = append(addresses, ip)
		}
		
		// Type AAAA (28) - IPv6
		if recordType == 28 && dataLen == 16 {
			ip := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				response[offset], response[offset+1],
				response[offset+2], response[offset+3],
				response[offset+4], response[offset+5],
				response[offset+6], response[offset+7],
				response[offset+8], response[offset+9],
				response[offset+10], response[offset+11],
				response[offset+12], response[offset+13],
				response[offset+14], response[offset+15])
			addresses = append(addresses, ip)
		}
		
		offset += dataLen
	}
	
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no A/AAAA records")
	}
	
	return addresses, nil
}

// skipDNSName skips a DNS name in the packet
func skipDNSName(data []byte, offset int) (int, error) {
	const maxJumps = 5
	jumps := 0
	
	for offset < len(data) {
		if data[offset] == 0 {
			return offset + 1, nil
		}
		
		// Compression pointer
		if data[offset]&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return 0, fmt.Errorf("truncated pointer")
			}
			
			pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if pointer >= offset {
				return 0, fmt.Errorf("forward reference")
			}
			if pointer >= len(data) {
				return 0, fmt.Errorf("pointer out of bounds")
			}
			
			jumps++
			if jumps > maxJumps {
				return 0, fmt.Errorf("too many jumps")
			}
			
			return offset + 2, nil
		}
		
		// Regular label
		labelLen := int(data[offset])
		if labelLen > 63 {
			return 0, fmt.Errorf("invalid label length")
		}
		
		offset += labelLen + 1
		if offset > len(data) {
			return 0, fmt.Errorf("label overflow")
		}
	}
	
	return 0, fmt.Errorf("unterminated name")
}

// probeBestIP probes all IPs and returns the one with lowest latency.
// P1-27: Optimized to reduce fingerprint - returns first IP if only one available,
// reducing TCP SYN probe patterns that can be detected by DPI.
func (r *BypassResolver) probeBestIP(ctx context.Context, addrs []string, port string) string {
	// P1-27: Fast path - if only one IP, return it without probing
	// This eliminates unnecessary TCP handshake that creates fingerprint
	if len(addrs) == 1 {
		return addrs[0]
	}
	
	// P1-27: Limit concurrent probes to reduce fingerprint visibility
	// Only probe up to 3 IPs instead of all to reduce SYN burst pattern
	maxProbes := len(addrs)
	if maxProbes > 3 {
		maxProbes = 3
	}
	
	type probeResult struct {
		ip      string
		latency time.Duration
	}

	ch := make(chan probeResult, maxProbes)
	var wg sync.WaitGroup

	probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
	defer probeCancel()

	for i := 0; i < maxProbes; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, port)
			start := time.Now()
			conn, err := r.tcpDialer.DialContext(probeCtx, "tcp", addr)
			if err != nil {
				ch <- probeResult{ip, time.Hour}
				return
			}
			conn.Close()
			ch <- probeResult{ip, time.Since(start)}
		}(addrs[i])
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	best := probeResult{ip: addrs[0], latency: time.Hour}
	for result := range ch {
		if result.latency < best.latency {
			best = result
		}
	}

	return best.ip
}

// ResolveIP resolves host to an IP address for the given port.
// If cfg has a BypassResolver, uses bypass-protected DNS and picks the optimal (lowest-latency) IP.
// Otherwise falls back to net.LookupIP and returns the first result.
func ResolveIP(cfg *BypassConfig, host, port string) (string, error) {
	if cfg != nil && cfg.Resolver != nil {
		return cfg.Resolver.ResolveBestIP(host, port)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("DNS resolve %s: %w", host, err)
	}
	return ips[0].String(), nil
}

