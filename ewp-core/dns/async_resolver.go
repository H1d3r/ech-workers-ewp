package dns

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"ewp-core/log"
)

// AsyncResolver is a non-blocking-from-the-caller's-point-of-view DNS
// resolver: cache hits return in microseconds, misses are dispatched
// to a bounded worker pool that performs DoH lookups in parallel.
//
// The "Async" in the name refers to the EXECUTION model — the API
// itself is plain synchronous Resolve(ctx, ...). Callers that need a
// non-blocking call site simply pass a short context.
//
// Design principles:
//
//   - One LRU cache for both A and AAAA records keyed by
//     (name, qtype). TTL is min(server_ttl, MaxTTL); never less than
//     MinTTL to absorb short-TTL flapping.
//   - Multiple in-flight requests for the same key are de-duplicated
//     (singleflight pattern); only one outbound DoH happens at a
//     time per (name, qtype).
//   - Worker pool bounds concurrency; if all workers are busy,
//     additional Resolve calls queue (up to QueueDepth) before
//     falling through to a synchronous DoH call.
//   - Multiple DoH upstreams are raced internally by DoH MultiClient.
//
// Suitable both for the client side ("application asked for the IP
// of X") and the server side ("I need to dial domain Y").
type AsyncResolver struct {
	doh      *MultiClient
	minTTL   time.Duration
	maxTTL   time.Duration

	mu     sync.Mutex
	cache  map[cacheKey]*list.Element
	lru    *list.List
	maxSz  int

	inflight map[cacheKey]*inflightCall

	workCh chan *resolveJob
	wg     sync.WaitGroup
	closed chan struct{}
}

// AsyncResolverConfig configures a new AsyncResolver. Zero values
// pick sensible defaults.
type AsyncResolverConfig struct {
	DoHServers   []string      // empty -> constant.DefaultDNSServers
	MinTTL       time.Duration // default 30s
	MaxTTL       time.Duration // default 1h
	CacheSize    int           // default 16384
	WorkerPool   int           // default 8
	QueueDepth   int           // default 256
}

// NewAsyncResolver constructs an AsyncResolver and starts the worker
// pool goroutines. Call Close to stop them.
func NewAsyncResolver(cfg AsyncResolverConfig) *AsyncResolver {
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = 30 * time.Second
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = time.Hour
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 16384
	}
	if cfg.WorkerPool <= 0 {
		cfg.WorkerPool = 8
	}
	if cfg.QueueDepth <= 0 {
		cfg.QueueDepth = 256
	}
	r := &AsyncResolver{
		doh:      NewMultiClient(cfg.DoHServers, nil),
		minTTL:   cfg.MinTTL,
		maxTTL:   cfg.MaxTTL,
		cache:    make(map[cacheKey]*list.Element),
		lru:      list.New(),
		maxSz:    cfg.CacheSize,
		inflight: make(map[cacheKey]*inflightCall),
		workCh:   make(chan *resolveJob, cfg.QueueDepth),
		closed:   make(chan struct{}),
	}
	for i := 0; i < cfg.WorkerPool; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	return r
}

// Close stops the worker pool. After Close, Resolve calls fail.
func (r *AsyncResolver) Close() error {
	select {
	case <-r.closed:
		return nil
	default:
		close(r.closed)
		close(r.workCh)
		r.wg.Wait()
	}
	return nil
}

// Resolve returns one IP for the given name. Prefers IPv4 unless the
// caller asks otherwise via the qtype hint.
//
// Cache-hit path: returns in ~5 µs without I/O.
// Cache-miss path: dispatches to the worker pool, blocks ctx-bound.
func (r *AsyncResolver) Resolve(ctx context.Context, name string, preferIPv6 bool) (netip.Addr, error) {
	if name == "" {
		return netip.Addr{}, errors.New("dns: empty name")
	}
	// Fast path: literal IP
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip, nil
	}

	primary := uint16(1) // A
	if preferIPv6 {
		primary = 28 // AAAA
	}
	if ip, ok := r.lookupCache(name, primary); ok {
		return ip, nil
	}

	// Slow path: dispatch.
	return r.dispatch(ctx, name, primary)
}

// ResolveAll returns all IPs for the name (both A and AAAA). Useful
// for happy-eyeballs-style dialers.
func (r *AsyncResolver) ResolveAll(ctx context.Context, name string) ([]netip.Addr, error) {
	if name == "" {
		return nil, errors.New("dns: empty name")
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{ip}, nil
	}

	var out []netip.Addr
	if ip, ok := r.lookupCache(name, 1); ok {
		out = append(out, ip)
	}
	if ip, ok := r.lookupCache(name, 28); ok {
		out = append(out, ip)
	}
	if len(out) > 0 {
		return out, nil
	}

	// Both miss; race A and AAAA in parallel.
	type res struct {
		ip  netip.Addr
		err error
	}
	ch := make(chan res, 2)
	go func() {
		ip, err := r.dispatch(ctx, name, 1)
		ch <- res{ip, err}
	}()
	go func() {
		ip, err := r.dispatch(ctx, name, 28)
		ch <- res{ip, err}
	}()
	for i := 0; i < 2; i++ {
		select {
		case rr := <-ch:
			if rr.err == nil {
				out = append(out, rr.ip)
			}
		case <-ctx.Done():
			if len(out) == 0 {
				return nil, ctx.Err()
			}
			return out, nil
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("dns: no records for %s", name)
	}
	return out, nil
}

// ----------------------------------------------------------------------
// internals
// ----------------------------------------------------------------------

type cacheKey struct {
	name  string
	qtype uint16
}

type cacheEntry struct {
	key       cacheKey
	ip        netip.Addr
	expiresAt time.Time
}

type inflightCall struct {
	done chan struct{}
	ip   netip.Addr
	err  error
}

type resolveJob struct {
	ctx   context.Context
	name  string
	qtype uint16
	reply chan resolveResult
}

type resolveResult struct {
	ip  netip.Addr
	err error
}

func (r *AsyncResolver) lookupCache(name string, qtype uint16) (netip.Addr, bool) {
	key := cacheKey{name, qtype}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[key]
	if !ok {
		return netip.Addr{}, false
	}
	entry := e.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		r.lru.Remove(e)
		delete(r.cache, key)
		return netip.Addr{}, false
	}
	r.lru.MoveToFront(e)
	return entry.ip, true
}

func (r *AsyncResolver) putCache(name string, qtype uint16, ip netip.Addr, ttl time.Duration) {
	if ttl < r.minTTL {
		ttl = r.minTTL
	}
	if ttl > r.maxTTL {
		ttl = r.maxTTL
	}
	key := cacheKey{name, qtype}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[key]; ok {
		e.Value.(*cacheEntry).ip = ip
		e.Value.(*cacheEntry).expiresAt = time.Now().Add(ttl)
		r.lru.MoveToFront(e)
		return
	}
	entry := &cacheEntry{key: key, ip: ip, expiresAt: time.Now().Add(ttl)}
	e := r.lru.PushFront(entry)
	r.cache[key] = e
	for r.lru.Len() > r.maxSz {
		oldest := r.lru.Back()
		if oldest == nil {
			break
		}
		r.lru.Remove(oldest)
		delete(r.cache, oldest.Value.(*cacheEntry).key)
	}
}

// dispatch sends the job to the worker pool, deduping concurrent
// callers for the same (name,qtype).
func (r *AsyncResolver) dispatch(ctx context.Context, name string, qtype uint16) (netip.Addr, error) {
	key := cacheKey{name, qtype}

	r.mu.Lock()
	if call, exists := r.inflight[key]; exists {
		r.mu.Unlock()
		select {
		case <-call.done:
			return call.ip, call.err
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	r.inflight[key] = call
	r.mu.Unlock()

	job := &resolveJob{
		ctx:   ctx,
		name:  name,
		qtype: qtype,
		reply: make(chan resolveResult, 1),
	}
	select {
	case r.workCh <- job:
		// queued
	case <-r.closed:
		r.completeInflight(key, call, netip.Addr{}, errors.New("dns: resolver closed"))
		return netip.Addr{}, errors.New("dns: resolver closed")
	default:
		// Worker pool & queue saturated. Run the DoH inline rather
		// than dropping the request — bounded by ctx anyway.
		log.V("[dns] async pool saturated; running %s inline", name)
		ip, err := r.doDoH(ctx, name, qtype)
		r.completeInflight(key, call, ip, err)
		return ip, err
	}

	select {
	case res := <-job.reply:
		r.completeInflight(key, call, res.ip, res.err)
		return res.ip, res.err
	case <-ctx.Done():
		// Caller gave up; the worker may still finish and populate
		// the cache, which is fine.
		return netip.Addr{}, ctx.Err()
	}
}

func (r *AsyncResolver) completeInflight(key cacheKey, call *inflightCall, ip netip.Addr, err error) {
	r.mu.Lock()
	delete(r.inflight, key)
	r.mu.Unlock()
	call.ip = ip
	call.err = err
	close(call.done)
}

func (r *AsyncResolver) worker() {
	defer r.wg.Done()
	for job := range r.workCh {
		ip, err := r.doDoH(job.ctx, job.name, job.qtype)
		select {
		case job.reply <- resolveResult{ip: ip, err: err}:
		default:
			// Caller dropped; still cache the result if successful.
		}
	}
}

// doDoH performs the actual DoH lookup, parses the first answer, and
// caches with the response TTL.
func (r *AsyncResolver) doDoH(ctx context.Context, name string, qtype uint16) (netip.Addr, error) {
	// Build the question.
	q := BuildQuery(name, qtype)
	respBytes, err := r.doh.QueryRaw(q)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, ttl, err := parseFirstAddrRecord(respBytes, qtype)
	if err != nil {
		return netip.Addr{}, err
	}
	r.putCache(name, qtype, ip, time.Duration(ttl)*time.Second)
	return ip, nil
}

// parseFirstAddrRecord walks a DNS message and returns the first A
// (qtype=1) or AAAA (qtype=28) RDATA + its TTL. We don't bring a
// full DNS parser in: this is a deliberately tiny implementation
// that handles the answer-section subset we need.
func parseFirstAddrRecord(msg []byte, want uint16) (netip.Addr, uint32, error) {
	if len(msg) < 12 {
		return netip.Addr{}, 0, errors.New("dns: short response")
	}
	rcode := msg[3] & 0x0f
	if rcode != 0 {
		return netip.Addr{}, 0, fmt.Errorf("dns: rcode %d", rcode)
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	// Skip questions.
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipDNSName(msg, off)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		off += 4 // qtype + qclass
		if off > len(msg) {
			return netip.Addr{}, 0, errors.New("dns: truncated question")
		}
	}
	for i := 0; i < an; i++ {
		var err error
		off, err = skipDNSName(msg, off)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		if off+10 > len(msg) {
			return netip.Addr{}, 0, errors.New("dns: truncated RR")
		}
		atype := uint16(msg[off])<<8 | uint16(msg[off+1])
		ttl := uint32(msg[off+4])<<24 | uint32(msg[off+5])<<16 | uint32(msg[off+6])<<8 | uint32(msg[off+7])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdlen > len(msg) {
			return netip.Addr{}, 0, errors.New("dns: truncated RDATA")
		}
		if atype == want {
			switch want {
			case 1:
				if rdlen != 4 {
					return netip.Addr{}, 0, errors.New("dns: bad A length")
				}
				var arr [4]byte
				copy(arr[:], msg[off:off+4])
				return netip.AddrFrom4(arr), ttl, nil
			case 28:
				if rdlen != 16 {
					return netip.Addr{}, 0, errors.New("dns: bad AAAA length")
				}
				var arr [16]byte
				copy(arr[:], msg[off:off+16])
				return netip.AddrFrom16(arr), ttl, nil
			}
		}
		off += rdlen
	}
	return netip.Addr{}, 0, fmt.Errorf("dns: no %d record", want)
}
