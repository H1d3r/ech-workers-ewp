package cfg

import (
	"time"

	"ewp-core/dns"
)

// BuildAsyncResolver constructs an *dns.AsyncResolver from the YAML
// upstream block. Returns nil when no servers are configured (caller
// then leaves the consuming outbound on its OS-resolver fallback).
func BuildAsyncResolver(c UpstreamDoHCfg) *dns.AsyncResolver {
	if len(c.Servers) == 0 {
		return nil
	}
	return dns.NewAsyncResolver(dns.AsyncResolverConfig{
		DoHServers: c.Servers,
		CacheSize:  c.CacheSize,
		WorkerPool: c.WorkerPool,
		MinTTL:     time.Duration(c.MinTTLSec) * time.Second,
		MaxTTL:     time.Duration(c.MaxTTLSec) * time.Second,
	})
}
