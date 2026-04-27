package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestAsyncResolver_CacheHit(t *testing.T) {
	r := NewAsyncResolver(AsyncResolverConfig{})
	defer r.Close()

	// Pre-populate cache directly to bypass DoH.
	r.putCache("example.com", 1, netip.MustParseAddr("1.2.3.4"), time.Hour)

	// 1000 concurrent lookups for the same name must all hit cache.
	var wg sync.WaitGroup
	wg.Add(1000)
	hits := make(chan netip.Addr, 1000)
	for i := 0; i < 1000; i++ {
		go func() {
			defer wg.Done()
			ip, err := r.Resolve(testCtx(t), "example.com", false)
			if err != nil {
				t.Errorf("Resolve: %v", err)
				return
			}
			hits <- ip
		}()
	}
	wg.Wait()
	close(hits)

	count := 0
	for ip := range hits {
		count++
		if ip.String() != "1.2.3.4" {
			t.Errorf("got %s, want 1.2.3.4", ip)
		}
	}
	if count != 1000 {
		t.Errorf("got %d hits, want 1000", count)
	}
}

func TestAsyncResolver_LiteralIP(t *testing.T) {
	r := NewAsyncResolver(AsyncResolverConfig{})
	defer r.Close()
	ip, err := r.Resolve(testCtx(t), "8.8.8.8", false)
	if err != nil {
		t.Fatalf("Resolve literal: %v", err)
	}
	if ip.String() != "8.8.8.8" {
		t.Errorf("got %s", ip)
	}
}

func TestAsyncResolver_TTLExpiry(t *testing.T) {
	r := NewAsyncResolver(AsyncResolverConfig{MinTTL: time.Millisecond})
	defer r.Close()
	r.putCache("a.example", 1, netip.MustParseAddr("1.1.1.1"), time.Millisecond)

	// First lookup hits cache.
	if _, ok := r.lookupCache("a.example", 1); !ok {
		t.Fatal("expected cache hit")
	}
	time.Sleep(50 * time.Millisecond)
	// MinTTL clamps stored ttl to 30s by default — but we constructed
	// with MinTTL=1ms, so this entry actually expires.
	if _, ok := r.lookupCache("a.example", 1); ok {
		t.Errorf("expected cache miss after TTL expiry")
	}
}

func TestAsyncResolver_LRUEvict(t *testing.T) {
	r := NewAsyncResolver(AsyncResolverConfig{CacheSize: 3})
	defer r.Close()
	r.putCache("a", 1, netip.MustParseAddr("1.1.1.1"), time.Hour)
	r.putCache("b", 1, netip.MustParseAddr("2.2.2.2"), time.Hour)
	r.putCache("c", 1, netip.MustParseAddr("3.3.3.3"), time.Hour)
	r.putCache("d", 1, netip.MustParseAddr("4.4.4.4"), time.Hour) // evicts "a"

	if _, ok := r.lookupCache("a", 1); ok {
		t.Error("expected 'a' to be evicted")
	}
	for _, n := range []string{"b", "c", "d"} {
		if _, ok := r.lookupCache(n, 1); !ok {
			t.Errorf("expected %q in cache", n)
		}
	}
}

func TestParseFirstAddrRecord_A(t *testing.T) {
	// Construct a minimal DNS message: header + 1 question (a.com A IN) + 1 A answer 4.3.2.1
	msg := []byte{
		// header
		0x12, 0x34, // ID
		0x81, 0x80, // flags QR=1 RD=1 RA=1 RCODE=0
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x01, // ANCOUNT=1
		0x00, 0x00, 0x00, 0x00,
		// Question: 1"a"3"com"0 type=A class=IN
		0x01, 'a', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		// Answer: name pointer 0xc00c, type=A, class=IN, ttl=300, rdlen=4, rdata=4.3.2.1
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x04,
		4, 3, 2, 1,
	}
	ip, ttl, err := parseFirstAddrRecord(msg, 1)
	if err != nil {
		t.Fatalf("parseFirstAddrRecord: %v", err)
	}
	if ip.String() != "4.3.2.1" {
		t.Errorf("ip = %s", ip)
	}
	if ttl != 300 {
		t.Errorf("ttl = %d", ttl)
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}
