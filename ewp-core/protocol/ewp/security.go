package ewp

import (
	"sync"
	"sync/atomic"
	"time"
)

// ── NonceCache ────────────────────────────────────────────────────────────────

// nonceCacheShards is the number of independent shard buckets.
// Must be a power of two; nonce[0] & (nonceCacheShards-1) selects the shard.
// 16 shards cuts worst-case lock contention by 16× under uniform nonce distribution.
const nonceCacheShards = 16

// nonceShard is one independent bucket with its own mutex and map.
// Padded to 64 bytes to prevent false sharing between adjacent shards on the
// same cache line. sync.Mutex(8) + map pointer(8) + padding(48) = 64.
type nonceShard struct {
	mu      sync.Mutex
	entries map[[12]byte]int64
	_       [48]byte
}

// NonceCache is a sharded replay-nonce cache.
// Each shard has an independent mutex, so 16 concurrent goroutines can
// add nonces without any lock contention as long as their nonces hash to
// different shards (expected with uniformly random nonces).
type NonceCache struct {
	shards [nonceCacheShards]nonceShard
	ttl    int64
}

// NewNonceCache creates a sharded Nonce cache.
func NewNonceCache() *NonceCache {
	cache := &NonceCache{
		ttl: TimeWindow * 2, // 240 秒
	}
	for i := range cache.shards {
		cache.shards[i].entries = make(map[[12]byte]int64)
	}
	go cache.cleanup()
	return cache
}

func (c *NonceCache) shardFor(nonce [12]byte) *nonceShard {
	return &c.shards[nonce[0]&(nonceCacheShards-1)]
}

// CheckAndAdd atomically checks and inserts a nonce into the appropriate shard.
// Returns true if the nonce was already present (replay attack detected).
func (c *NonceCache) CheckAndAdd(nonce [12]byte) bool {
	now := time.Now().Unix()
	s := c.shardFor(nonce)

	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, exists := s.entries[nonce]; exists && exp > now {
		return true
	}
	s.entries[nonce] = now + c.ttl
	return false
}

// cleanup sweeps all shards every 60 seconds, deleting expired entries.
func (c *NonceCache) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		for i := range c.shards {
			s := &c.shards[i]
			s.mu.Lock()
			for nonce, exp := range s.entries {
				if exp <= now {
					delete(s.entries, nonce)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

// RateLimiter provides per-IP rate limiting with a two-phase lock strategy:
//   - Banned IPs are checked via an atomic read (no mutex at all).
//   - Non-banned IPs acquire a write lock only to increment the counter.
//
// This eliminates the global write lock from the common path (established
// connections below the rate limit).
type RateLimiter struct {
	mu      sync.RWMutex
	entries map[string]*rateLimitEntry
	maxRate int
	banTime time.Duration
}

type rateLimitEntry struct {
	mu          sync.Mutex // guards count and resetTime
	count       int
	resetTime   int64
	bannedUntil atomic.Int64 // read without any mutex; written under entry.mu
}

// NewRateLimiter creates a rate limiter.
// maxRate: maximum requests per second per IP.
// banTime: how long to ban an IP that exceeds the rate.
func NewRateLimiter(maxRate int, banTime time.Duration) *RateLimiter {
	rl := &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
		maxRate: maxRate,
		banTime: banTime,
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the IP is allowed, false if banned or rate-exceeded.
//
// Fast path (banned IP): one atomic.Load, zero mutex operations.
// Normal path (known IP, below limit): RLock to fetch entry pointer,
// then per-entry Mutex to increment counter — avoids global write lock.
func (r *RateLimiter) Allow(ip string) bool {
	now := time.Now().Unix()

	// ── Fast path: try to get the entry under read lock ──────────────────────
	r.mu.RLock()
	entry, exists := r.entries[ip]
	r.mu.RUnlock()

	if exists {
		// Banned check: atomic, no mutex.
		if entry.bannedUntil.Load() > now {
			return false
		}
		// Counter update: per-entry mutex (not global write lock).
		entry.mu.Lock()
		defer entry.mu.Unlock()

		// Re-check ban after acquiring entry lock (another goroutine may have
		// just set it between our atomic read and this lock).
		if entry.bannedUntil.Load() > now {
			return false
		}
		if entry.resetTime <= now {
			entry.count = 1
			entry.resetTime = now + 1
			return true
		}
		entry.count++
		if entry.count > r.maxRate {
			entry.bannedUntil.Store(now + int64(r.banTime.Seconds()))
			return false
		}
		return true
	}

	// ── Slow path: new IP — global write lock to insert ──────────────────────
	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check: another goroutine may have inserted between RUnlock and Lock.
	if entry, exists = r.entries[ip]; exists {
		if entry.bannedUntil.Load() > now {
			return false
		}
		entry.mu.Lock()
		defer entry.mu.Unlock()
		entry.count++
		if entry.count > r.maxRate {
			entry.bannedUntil.Store(now + int64(r.banTime.Seconds()))
			return false
		}
		return true
	}
	r.entries[ip] = &rateLimitEntry{count: 1, resetTime: now + 1}
	return true
}

// RecordFailure extends the ban for an IP after an auth failure.
func (r *RateLimiter) RecordFailure(ip string) {
	now := time.Now().Unix()
	banUntil := now + int64(r.banTime.Seconds())

	r.mu.RLock()
	entry, exists := r.entries[ip]
	r.mu.RUnlock()

	if exists {
		entry.bannedUntil.Store(banUntil)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, exists = r.entries[ip]; exists {
		entry.bannedUntil.Store(banUntil)
		return
	}
	e := &rateLimitEntry{count: 1, resetTime: now + 1}
	e.bannedUntil.Store(banUntil)
	r.entries[ip] = e
}

// cleanup removes entries that are no longer banned and whose counters have reset.
func (r *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		r.mu.Lock()
		for ip, entry := range r.entries {
			if entry.bannedUntil.Load() <= now && entry.resetTime <= now {
				delete(r.entries, ip)
			}
		}
		r.mu.Unlock()
	}
}
