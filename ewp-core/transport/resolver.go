package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// BypassResolver resolves hostnames using a DNS connection that bypasses the TUN device.
// When multiple IPs are returned, all are probed in parallel and the one with the lowest
// TCP handshake latency is returned (optimal CDN edge-node selection).
type BypassResolver struct {
	resolver  *net.Resolver
	tcpDialer *net.Dialer
}

// NewBypassResolver creates a resolver whose DNS queries use the bypass TCP dialer,
// ensuring DNS traffic does not loop through the TUN device.
// dnsServer must be "host:port" (e.g. "8.8.8.8:53"). Empty defaults to "8.8.8.8:53".
func NewBypassResolver(cfg *BypassConfig, dnsServer string) *BypassResolver {
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}
	server := dnsServer
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return cfg.TCPDialer.DialContext(ctx, "tcp", server)
		},
	}
	return &BypassResolver{resolver: r, tcpDialer: cfg.TCPDialer}
}

// ResolveBestIP resolves host and returns the IP with the lowest TCP latency on port.
// All resolved IPs are probed concurrently; the fastest one is returned.
// Falls back to the first resolved IP if all probes time out.
func (r *BypassResolver) ResolveBestIP(host, port string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := r.resolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("bypass DNS resolve %s: %w", host, err)
	}

	if len(addrs) == 1 {
		return addrs[0], nil
	}

	type probeResult struct {
		ip      string
		latency time.Duration
	}

	ch := make(chan probeResult, len(addrs))
	var wg sync.WaitGroup

	probeCtx, probeCancel := context.WithTimeout(ctx, 3*time.Second)
	defer probeCancel()

	for _, ip := range addrs {
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
		}(ip)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	best := probeResult{ip: addrs[0], latency: time.Hour}
	for r := range ch {
		if r.latency < best.latency {
			best = r
		}
	}

	if best.latency == time.Hour {
		return addrs[0], nil
	}
	return best.ip, nil
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
