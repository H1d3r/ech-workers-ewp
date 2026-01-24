package ewp

import (
	"encoding/hex"
	"sync"
	"time"
)

// NonceCache 实现 Nonce 去重缓存（防重放攻击）
// 保留最近 TimeWindow * 2 秒内的所有 Nonce
type NonceCache struct {
	mu      sync.RWMutex
	entries map[string]int64 // nonce -> expireTime
	ttl     int64             // 过期时间（秒）
}

// NewNonceCache 创建 Nonce 缓存
func NewNonceCache() *NonceCache {
	cache := &NonceCache{
		entries: make(map[string]int64),
		ttl:     TimeWindow * 2, // 240 秒
	}
	
	// 启动清理 goroutine
	go cache.cleanup()
	
	return cache
}

// Check 检查 Nonce 是否已存在（存在则为重放攻击）
// 返回 true 表示 Nonce 已存在（重放攻击）
func (c *NonceCache) Check(nonce [12]byte) bool {
	key := hex.EncodeToString(nonce[:])
	now := time.Now().Unix()
	
	c.mu.RLock()
	expireTime, exists := c.entries[key]
	c.mu.RUnlock()
	
	if exists && expireTime > now {
		return true // 重放攻击！
	}
	
	return false
}

// Add 添加 Nonce 到缓存
func (c *NonceCache) Add(nonce [12]byte) {
	key := hex.EncodeToString(nonce[:])
	expireTime := time.Now().Unix() + c.ttl
	
	c.mu.Lock()
	c.entries[key] = expireTime
	c.mu.Unlock()
}

// cleanup 定期清理过期的 Nonce（每 60 秒）
func (c *NonceCache) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now().Unix()
		
		c.mu.Lock()
		for key, expireTime := range c.entries {
			if expireTime <= now {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// RateLimiter 实现 IP 级别的速率限制（防 DoS）
type RateLimiter struct {
	mu               sync.RWMutex
	entries          map[string]*rateLimitEntry
	maxRate          int           // 每秒最大请求数
	banTime          time.Duration // 封禁时长
	failureThreshold int           // 失败次数阈值（达到后才封禁）
}

type rateLimitEntry struct {
	count         int
	resetTime     int64
	bannedUntil   int64
	failureCount  int   // 失败计数器
	lastFailTime  int64 // 上次失败时间
}

// NewRateLimiter 创建速率限制器
// maxRate: 每秒最大请求数
// banTime: 超限后的封禁时长
// failureThreshold: 失败次数阈值（达到后才封禁，0表示首次失败就封禁）
func NewRateLimiter(maxRate int, banTime time.Duration, failureThreshold int) *RateLimiter {
	if failureThreshold < 1 {
		failureThreshold = 1 // 至少1次
	}
	
	limiter := &RateLimiter{
		entries:          make(map[string]*rateLimitEntry),
		maxRate:          maxRate,
		banTime:          banTime,
		failureThreshold: failureThreshold,
	}
	
	// 启动清理 goroutine
	go limiter.cleanup()
	
	return limiter
}

// Allow 检查 IP 是否允许请求
// 返回 true 表示允许，false 表示拒绝（被封禁或超限）
func (r *RateLimiter) Allow(ip string) bool {
	now := time.Now().Unix()
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	entry, exists := r.entries[ip]
	if !exists {
		// 新 IP，创建条目
		r.entries[ip] = &rateLimitEntry{
			count:     1,
			resetTime: now + 1,
		}
		return true
	}
	
	// 检查是否被封禁
	if entry.bannedUntil > now {
		return false
	}
	
	// 检查是否需要重置计数器
	if entry.resetTime <= now {
		entry.count = 1
		entry.resetTime = now + 1
		return true
	}
	
	// 增加计数
	entry.count++
	
	// 检查是否超限
	if entry.count > r.maxRate {
		entry.bannedUntil = now + int64(r.banTime.Seconds())
		return false
	}
	
	return true
}

// RecordFailure 记录认证失败（渐进式封禁）
func (r *RateLimiter) RecordFailure(ip string) {
	now := time.Now().Unix()
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	entry, exists := r.entries[ip]
	if !exists {
		// 新 IP 首次失败，只记录不封禁
		r.entries[ip] = &rateLimitEntry{
			count:        1,
			resetTime:    now + 1,
			failureCount: 1,
			lastFailTime: now,
		}
		return
	}
	
	// 如果距离上次失败超过60秒，重置失败计数器（容忍偶发错误）
	if now-entry.lastFailTime > 60 {
		entry.failureCount = 1
		entry.lastFailTime = now
		return
	}
	
	// 累加失败次数
	entry.failureCount++
	entry.lastFailTime = now
	
	// 只有连续失败达到阈值才封禁
	if entry.failureCount >= r.failureThreshold {
		entry.bannedUntil = now + int64(r.banTime.Seconds())
	}
}

// RecordSuccess 记录认证成功（重置失败计数器）
func (r *RateLimiter) RecordSuccess(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if entry, exists := r.entries[ip]; exists {
		entry.failureCount = 0
		entry.lastFailTime = 0
	}
}

// cleanup 定期清理过期的条目（每 5 分钟）
func (r *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now().Unix()
		
		r.mu.Lock()
		for ip, entry := range r.entries {
			// 清理已解封且计数器已重置的条目
			if entry.bannedUntil <= now && entry.resetTime <= now {
				delete(r.entries, ip)
			}
		}
		r.mu.Unlock()
	}
}
