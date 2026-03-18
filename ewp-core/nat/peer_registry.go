package nat

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

func init() {
	if sz := unsafe.Sizeof(PeerEntry{}); sz != 32 {
		panic(fmt.Sprintf("nat.PeerEntry: size=%d want 32", sz))
	}
	if sz := unsafe.Sizeof(realShard{}); sz != 64 {
		panic(fmt.Sprintf("nat.realShard: size=%d want 64 (one cache line)", sz))
	}
}

// vipPoolSize is the total number of table slots (indices 0..131069).
// Valid offsets are 1..131069; index 0 maps to 198.18.0.0 (network addr, skip).
const vipPoolSize = 131070

const (
	// v field bit layout — packs an IPv4 realAddr into 8 bytes:
	//   bits 63-32: IPv4 address (big-endian)
	//   bits 31-16: UDP port
	//   bits 15-8:  flags
	//   bits  7-0:  reserved
	bitOccupied uint64 = 1 << 8
	bitIPv4     uint64 = 1 << 9
)

// PeerEntry — 32 bytes, ZERO pointer fields.
//
// The entire [vipPoolSize]PeerEntry array is a no-scan span from the GC's
// perspective: neither atomic.Uint64 nor atomic.Int64 contain pointer fields,
// so the GC mark phase skips 4.2 MB of vipTable completely.
//
//	offset  0 │ v          8 B │ packed realIP+port+flags (IPv4 fast path)
//	offset  8 │ lastActive 8 B │ Unix nanosecond (eviction clock)
//	offset 16 │ _pad      16 B │ pad to 32 bytes
type PeerEntry struct {
	v          atomic.Uint64 // zero-pointer atomic
	lastActive atomic.Int64  // zero-pointer atomic
	_pad       [16]byte
}

// realShard — 64 bytes, one CPU L1 cache line per shard.
//
// map[uint64]uint32: both key and value are pointer-free types.
// GC only scans the bucket-array header (O(buckets)), not entry contents.
//
//	offset  0 │ mu   24 B │ sync.RWMutex
//	offset 24 │ m     8 B │ map header (pointer)
//	offset 32 │ _pad 32 B │ cache-line fill
type realShard struct {
	mu   sync.RWMutex
	m    map[uint64]uint32 // encAddrPort(realAddr) → vipTable offset
	_pad [32]byte
}

// PeerRegistry is the Full Cone NAT vIP anchor contract.
// All methods must be safe for concurrent use without external locking.
type PeerRegistry interface {
	// Allocate returns a stable virtual IP for the given real peer endpoint.
	// Idempotent: repeated calls with the same realAddr return the same vIP.
	Allocate(realAddr netip.AddrPort) netip.Addr

	// LookupReal returns the real peer endpoint for a given virtual IP.
	// ok=false if the vIP has never been allocated or has been evicted.
	LookupReal(vIP netip.Addr) (realAddr netip.AddrPort, ok bool)

	// EvictStale removes sessions whose LastActive is before timeoutNano.
	// Must NOT be called on the packet hot path.
	EvictStale(timeoutNano int64)
}

// ShardedRegistry implements PeerRegistry.
//
//   - vipTable:     ~4.2 MB contiguous, pointer-free. LookupReal = single atomic.Load.
//   - shards:       16 KB of 256 independently-lockable reverse-index partitions.
//   - vipNext:      atomic pool cursor; wraps across 1..131069.
//   - droppedIPv6:  counter of Allocate calls rejected because the peer is IPv6.
//     IPv6 peers cannot be packed into the 8-byte PeerEntry.v field; they are
//     dropped with a counter increment and a log line. Use DroppedIPv6Count() to
//     observe this in metrics.
type ShardedRegistry struct {
	vipTable    [vipPoolSize]PeerEntry
	shards      [256]realShard
	vipNext     atomic.Uint32
	droppedIPv6 atomic.Int64
}

// DroppedIPv6Count returns the total number of Allocate calls that were rejected
// because the peer address was IPv6 (not supported by the flat-array pool).
func (r *ShardedRegistry) DroppedIPv6Count() int64 {
	return r.droppedIPv6.Load()
}

var _ PeerRegistry = (*ShardedRegistry)(nil)

// NewShardedRegistry allocates and initialises a ShardedRegistry.
func NewShardedRegistry() *ShardedRegistry {
	r := &ShardedRegistry{}
	for i := range r.shards {
		r.shards[i].m = make(map[uint64]uint32, 64)
	}
	r.vipNext.Store(1)
	return r
}

// LookupReal is completely lock-free: one offsetFromVIP arithmetic op + one
// atomic.Load on the flat table. No allocation, no contention.
func (r *ShardedRegistry) LookupReal(vIP netip.Addr) (netip.AddrPort, bool) {
	offset, ok := offsetFromVIP(vIP)
	if !ok {
		return netip.AddrPort{}, false
	}
	v := r.vipTable[offset].v.Load()
	if v&bitOccupied == 0 {
		return netip.AddrPort{}, false
	}
	return decodeAddrPort(v), true
}

// Allocate returns a stable vIP for the given real peer endpoint.
//
// Fast path (entry already exists, RLock): 1 map lookup + 1 atomic.Load + 1 atomic.Store.
// Slow path (new entry, WLock): 1 atomic.Add + 1 map insert + 2 atomic.Stores.
// Stale reverse-map entries (slot evicted by pool wrap) are cleaned lazily.
//
// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are silently unmapped to IPv4.
// Pure IPv6 peers are rejected: zero addr returned, droppedIPv6 counter incremented.
func (r *ShardedRegistry) Allocate(realAddr netip.AddrPort) netip.Addr {
	realAddr = netip.AddrPortFrom(realAddr.Addr().Unmap(), realAddr.Port())
	if !realAddr.Addr().Is4() {
		r.droppedIPv6.Add(1)
		return netip.Addr{}
	}

	enc := encAddrPort(realAddr)
	si := shardOf(realAddr)
	shard := &r.shards[si]
	now := time.Now().UnixNano()

	// Fast path: entry exists and vipTable slot still belongs to this realAddr.
	shard.mu.RLock()
	offset, exists := shard.m[enc]
	if exists && r.vipTable[offset].v.Load() == enc {
		r.vipTable[offset].lastActive.Store(now)
		shard.mu.RUnlock()
		return vipFromOffset(offset)
	}
	shard.mu.RUnlock()

	// Slow path.
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Double-check after acquiring write lock.
	offset, exists = shard.m[enc]
	if exists && r.vipTable[offset].v.Load() == enc {
		r.vipTable[offset].lastActive.Store(now)
		return vipFromOffset(offset)
	}
	// Stale reverse-map entry: the slot was overwritten by a pool wrap.
	// Clean it up now so map size stays bounded.
	if exists {
		delete(shard.m, enc)
	}

	newOffset := r.claimSlot()
	r.vipTable[newOffset].v.Store(enc)
	r.vipTable[newOffset].lastActive.Store(now)
	shard.m[enc] = newOffset
	return vipFromOffset(newOffset)
}

// EvictStale does a single linear pass over vipTable, CAS-clearing entries
// whose lastActive is older than timeoutNano.
//
// Reverse-map stale entries are NOT removed here — they are cleaned lazily
// by the next Allocate call for that realAddr. This avoids the need for
// cross-shard locking inside the eviction loop.
//
// Call from a background goroutine, NOT the packet hot path.
func (r *ShardedRegistry) EvictStale(timeoutNano int64) {
	for i := uint32(1); i < vipPoolSize; i++ {
		e := &r.vipTable[i]
		v := e.v.Load()
		if v&bitOccupied == 0 {
			continue
		}
		if e.lastActive.Load() >= timeoutNano {
			continue
		}
		// CAS: if another goroutine just re-claimed this slot with a new entry,
		// the CAS fails and we correctly leave the new entry untouched.
		e.v.CompareAndSwap(v, 0)
	}
}

// setLastActiveForTest sets LastActive directly via the vipTable offset.
// O(1); avoids the full shard scan of the stub implementation.
func (r *ShardedRegistry) setLastActiveForTest(vip netip.Addr, nanoTS int64) {
	offset, ok := offsetFromVIP(vip)
	if !ok {
		return
	}
	r.vipTable[offset].lastActive.Store(nanoTS)
}

// claimSlot atomically advances vipNext and returns the claimed offset (1..131069).
// When the pool exhausts, the cursor wraps back to 1 via CAS — the evicted slot's
// reverse-map entry becomes stale and is cleaned lazily on next Allocate.
func (r *ShardedRegistry) claimSlot() uint32 {
	for {
		// Add(1) returns the NEW value; subtract 1 to get the offset we claimed.
		offset := r.vipNext.Add(1) - 1
		if offset > 0 && offset < vipPoolSize {
			return offset
		}
		// Cursor overflowed valid range; one goroutine resets it, others retry.
		cur := r.vipNext.Load()
		if cur >= vipPoolSize {
			r.vipNext.CompareAndSwap(cur, 1)
		}
	}
}

// --- Encoding helpers — all constant-foldable, zero allocation ---

// encAddrPort packs an IPv4 AddrPort into a uint64.
// Result is always non-zero (bitOccupied | bitIPv4 are always set).
func encAddrPort(ap netip.AddrPort) uint64 {
	b := ap.Addr().As4()
	return uint64(b[0])<<56 | uint64(b[1])<<48 |
		uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(ap.Port())<<16 |
		bitOccupied | bitIPv4
}

// decodeAddrPort reconstructs an IPv4 AddrPort from a packed uint64.
func decodeAddrPort(v uint64) netip.AddrPort {
	ip4 := [4]byte{byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32)}
	return netip.AddrPortFrom(netip.AddrFrom4(ip4), uint16(v>>16))
}

// vipFromOffset converts pool offset → 198.18.x.x virtual IP.
//
//	offset 1     → 198.18.0.1
//	offset 65535 → 198.18.255.255
//	offset 65536 → 198.19.0.0
//	offset 131069→ 198.19.255.253
func vipFromOffset(offset uint32) netip.Addr {
	const base = uint32(198)<<24 | uint32(18)<<16
	v := base + offset
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// offsetFromVIP is the inverse of vipFromOffset.
func offsetFromVIP(vip netip.Addr) (uint32, bool) {
	if !vip.Is4() {
		return 0, false
	}
	b := vip.As4()
	if b[0] != 198 || (b[1] != 18 && b[1] != 19) {
		return 0, false
	}
	const base = uint32(198)<<24 | uint32(18)<<16
	val := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	offset := val - base
	if offset == 0 || offset >= vipPoolSize {
		return 0, false
	}
	return offset, true
}

// shardOf derives the shard index for a realAddr via XOR folding.
func shardOf(addr netip.AddrPort) uint8 {
	b := addr.Addr().As4()
	p := addr.Port()
	return b[0] ^ b[1] ^ b[2] ^ b[3] ^ byte(p>>8) ^ byte(p)
}
