package tun

import (
	"context"
	"time"

	"ewp-core/dns"
	"ewp-core/nat"
)

// newHandlerCore initialises a Handler + ShardedRegistry pair from cfg.
//
//   - Always allocates a ShardedRegistry and wires it via SetPeerRegistry.
//   - DisableFakeIP=false (default): also creates a FakeIPPool (backward compat).
//   - DisableFakeIP=true  (Normal Mode): fakeIPPool stays nil; peer vIPs only.
func newHandlerCore(ctx context.Context, cfg *Config, writer UDPWriter) (*Handler, *nat.ShardedRegistry) {
	h := NewHandler(ctx, cfg.Transport, writer)

	reg := nat.NewShardedRegistry()
	h.SetPeerRegistry(reg)

	if !cfg.DisableFakeIP {
		h.SetFakeIPPool(dns.NewFakeIPPool())
	}

	return h, reg
}

// startEviction manages the EvictStale background goroutine for reg.
// It ticks every interval, evicting entries whose lastActive is older than evictAfter.
// The goroutine exits when ctx is cancelled — zero goroutine leak.
func startEviction(ctx context.Context, reg *nat.ShardedRegistry, interval, evictAfter time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if evictAfter <= 0 {
		evictAfter = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().Add(-evictAfter).UnixNano()
				reg.EvictStale(cutoff)
			}
		}
	}()
}
