package tls

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"ewp-core/dns"
	echlog "ewp-core/log"
)

// ECHManager manages ECH configuration with TTL-based caching
type ECHManager struct {
	domain        string
	dnsServers    []string // P0-12: multiple DoH servers for redundancy
	echList       []byte
	lastFetch     time.Time
	cacheTTL      time.Duration
	mu            sync.RWMutex
	dnsClient     interface{} // *dns.Client or *dns.MultiClient
	stopClean     chan struct{}
	cleanOnce     sync.Once
	strictMode    bool // P0-12: if true, fail on ECH errors instead of fallback
}

// SetBypassDialer replaces the internal DoH client with one that uses the provided
// dialer for all TCP connections. Call this before the first Refresh() when running
// in TUN mode so that the initial ECH fetch bypasses the TUN device and avoids a
// bootstrap deadlock (tunnel not yet established → cannot proxy the DoH request).
func (m *ECHManager) SetBypassDialer(d *net.Dialer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// P0-12: use MultiClient for redundancy
	if len(m.dnsServers) > 1 {
		m.dnsClient = dns.NewMultiClient(m.dnsServers, d)
	} else {
		server := m.dnsServers[0]
		m.dnsClient = dns.NewClientWithDialer(server, d)
	}
}

// NewECHManager creates a new ECH manager with 1-hour cache TTL
// P0-12: accepts multiple DNS servers; uses the first if only one provided
func NewECHManager(domain string, dnsServers ...string) *ECHManager {
	return NewECHManagerWithTTL(domain, 1*time.Hour, false, dnsServers...)
}

// NewECHManagerWithTTL creates a new ECH manager with custom cache TTL
// P0-12: strictMode=true means ECH failures abort connection instead of fallback
func NewECHManagerWithTTL(domain string, ttl time.Duration, strictMode bool, dnsServers ...string) *ECHManager {
	if len(dnsServers) == 0 {
		dnsServers = []string{dnsServers[0]} // use first default
	}
	
	var client interface{}
	if len(dnsServers) > 1 {
		client = dns.NewMultiClient(dnsServers, nil)
	} else {
		client = dns.NewClient(dnsServers[0])
	}
	
	m := &ECHManager{
		domain:     domain,
		dnsServers: dnsServers,
		cacheTTL:   ttl,
		dnsClient:  client,
		stopClean:  make(chan struct{}),
		strictMode: strictMode,
	}
	m.startCleanupRoutine()
	return m
}

// Refresh fetches and updates ECH configuration
func (m *ECHManager) Refresh() error {
	echlog.Printf("[ECH] Refreshing configuration...")

	m.mu.RLock()
	client := m.dnsClient
	m.mu.RUnlock()

	var echBase64 string
	var err error
	
	// P0-12: support both single and multi-client
	switch c := client.(type) {
	case *dns.Client:
		echBase64, err = c.QueryHTTPS(m.domain)
	case *dns.MultiClient:
		echBase64, err = c.QueryHTTPS(m.domain)
	default:
		return fmt.Errorf("invalid DNS client type")
	}
	
	if err != nil {
		return fmt.Errorf("DNS query failed: %w", err)
	}

	if echBase64 == "" {
		return errors.New("no ECH parameter found")
	}

	// Decode base64 ECH data
	echList, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("failed to decode ECH config: %w", err)
	}

	// Update ECH list and fetch timestamp
	m.mu.Lock()
	m.echList = echList
	m.lastFetch = time.Now()
	m.mu.Unlock()

	echlog.Printf("[ECH] Configuration loaded, length: %d bytes, TTL: %v", len(echList), m.cacheTTL)
	return nil
}

// Get returns the current ECH configuration, auto-refreshing if expired
// P0-12: in strict mode, returns error instead of using expired cache
func (m *ECHManager) Get() ([]byte, error) {
	m.mu.RLock()
	needsRefresh := m.isExpired()
	strictMode := m.strictMode
	m.mu.RUnlock()

	// Auto-refresh if cache expired
	if needsRefresh {
		echlog.Printf("[ECH] Cache expired, auto-refreshing...")
		if err := m.Refresh(); err != nil {
			echlog.Printf("[ECH] Auto-refresh failed: %v", err)
			
			// P0-12: strict mode - fail instead of fallback
			if strictMode {
				return nil, fmt.Errorf("ECH refresh failed in strict mode: %w", err)
			}
			
			// Fallback: return cached data even if expired
			m.mu.RLock()
			defer m.mu.RUnlock()
			if len(m.echList) > 0 {
				echlog.Printf("[ECH] Using expired cache as fallback")
				return m.echList, nil
			}
			return nil, fmt.Errorf("refresh failed and no cache available: %w", err)
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.echList) == 0 {
		return nil, errors.New("ECH configuration not loaded")
	}

	return m.echList, nil
}

// UpdateFromRetry updates ECH configuration from server's retry config
// This is called when server returns ECHRejectionError with RetryConfigList
func (m *ECHManager) UpdateFromRetry(retryConfigList []byte) error {
	if len(retryConfigList) == 0 {
		return errors.New("empty retry config list")
	}

	m.mu.Lock()
	m.echList = retryConfigList
	m.lastFetch = time.Now()
	m.mu.Unlock()

	echlog.Printf("[ECH] Updated configuration from server retry, length: %d bytes", len(retryConfigList))
	return nil
}

// isExpired checks if the cache has expired (caller must hold at least RLock)
func (m *ECHManager) isExpired() bool {
	if m.lastFetch.IsZero() {
		return true
	}
	return time.Since(m.lastFetch) > m.cacheTTL
}

// GetDomain returns the ECH domain
func (m *ECHManager) GetDomain() string {
	return m.domain
}

// GetDNSServer returns the DNS server URL (first one if multiple)
func (m *ECHManager) GetDNSServer() string {
	if len(m.dnsServers) > 0 {
		return m.dnsServers[0]
	}
	return ""
}

// GetDNSServers returns all configured DNS servers
func (m *ECHManager) GetDNSServers() []string {
	return m.dnsServers
}

// startCleanupRoutine starts a background goroutine to periodically check and refresh expired cache
func (m *ECHManager) startCleanupRoutine() {
	m.cleanOnce.Do(func() {
		go m.cleanupLoop()
	})
}

// cleanupLoop runs periodically to check and refresh expired cache
func (m *ECHManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.RLock()
			expired := m.isExpired()
			m.mu.RUnlock()

			if expired {
				echlog.Printf("[ECH] Background cleanup: cache expired, refreshing...")
				if err := m.Refresh(); err != nil {
					echlog.Printf("[ECH] Background refresh failed: %v", err)
				}
			}
		case <-m.stopClean:
			echlog.Printf("[ECH] Cleanup routine stopped")
			return
		}
	}
}

// Stop stops the background cleanup routine
func (m *ECHManager) Stop() {
	close(m.stopClean)
}

// GetCacheAge returns the age of the current cache
func (m *ECHManager) GetCacheAge() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.lastFetch.IsZero() {
		return 0
	}
	return time.Since(m.lastFetch)
}

// GetCacheTTL returns the configured cache TTL
func (m *ECHManager) GetCacheTTL() time.Duration {
	return m.cacheTTL
}
