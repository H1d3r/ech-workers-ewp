package dns

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// FakeIPPool allocates fake IPs from a reserved range and maintains bidirectional
// domain ↔ fakeIP mappings. Used to eliminate DNS tunnel latency by returning
// instant fake responses, letting the proxy server handle real DNS resolution.
//
// IPv4 range: 198.18.0.1 – 198.19.255.254 (131,070 addresses)
// IPv6 range: fc00::1 – fc00::fffe (65,534 addresses)
type FakeIPPool struct {
	mu sync.RWMutex

	// IPv4 pool: 198.18.0.0/15
	ip4Base  netip.Addr // 198.18.0.0
	ip4Next  uint32     // next offset (wraps at ip4Size)
	ip4Size  uint32     // total allocatable addresses
	ip4Start uint32     // first usable offset (skip .0)

	// IPv6 pool: fc00::/112
	ip6Base  netip.Addr
	ip6Next  uint16
	ip6Size  uint16
	ip6Start uint16

	// Bidirectional mappings
	domainToIP4 map[string]netip.Addr // "google.com" → 198.18.0.1
	domainToIP6 map[string]netip.Addr // "google.com" → fc00::1
	ip4ToDomain map[netip.Addr]string // 198.18.0.1 → "google.com"
	ip6ToDomain map[netip.Addr]string // fc00::1 → "google.com"
}

// NewFakeIPPool creates a new FakeIP pool.
func NewFakeIPPool() *FakeIPPool {
	return &FakeIPPool{
		ip4Base:  netip.AddrFrom4([4]byte{198, 18, 0, 0}),
		ip4Next:  1, // start at 198.18.0.1 (skip .0)
		ip4Size:  131070,
		ip4Start: 1,

		ip6Base:  netip.AddrFrom16([16]byte{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		ip6Next:  1,
		ip6Size:  65534,
		ip6Start: 1,

		domainToIP4: make(map[string]netip.Addr, 4096),
		domainToIP6: make(map[string]netip.Addr, 4096),
		ip4ToDomain: make(map[netip.Addr]string, 4096),
		ip6ToDomain: make(map[netip.Addr]string, 4096),
	}
}

// LookupByIP returns the domain mapped to the given IP.
// Returns ("", false) if the IP is not a fake IP.
func (p *FakeIPPool) LookupByIP(ip netip.Addr) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if ip.Is4() {
		domain, ok := p.ip4ToDomain[ip]
		return domain, ok
	}
	domain, ok := p.ip6ToDomain[ip]
	return domain, ok
}

// IsFakeIP returns true if the given address is within the fake IP range.
func (p *FakeIPPool) IsFakeIP(ip netip.Addr) bool {
	if ip.Is4() {
		b := ip.As4()
		return b[0] == 198 && (b[1] == 18 || b[1] == 19)
	}
	if ip.Is6() {
		b := ip.As16()
		return b[0] == 0xfc && b[1] == 0x00
	}
	return false
}

// AllocateIPv4 returns a fake IPv4 for the given domain.
// If the domain already has a mapping, returns the existing one.
func (p *FakeIPPool) AllocateIPv4(domain string) netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.domainToIP4[domain]; ok {
		return existing
	}

	ip := p.nextIPv4()

	// If this IP was previously allocated to another domain, evict it
	if old, exists := p.ip4ToDomain[ip]; exists {
		delete(p.domainToIP4, old)
	}

	p.domainToIP4[domain] = ip
	p.ip4ToDomain[ip] = domain
	return ip
}

// AllocateIPv6 returns a fake IPv6 for the given domain.
func (p *FakeIPPool) AllocateIPv6(domain string) netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.domainToIP6[domain]; ok {
		return existing
	}

	ip := p.nextIPv6()

	if old, exists := p.ip6ToDomain[ip]; exists {
		delete(p.domainToIP6, old)
	}

	p.domainToIP6[domain] = ip
	p.ip6ToDomain[ip] = domain
	return ip
}

// nextIPv4 allocates the next IPv4 from the pool (caller must hold mu).
func (p *FakeIPPool) nextIPv4() netip.Addr {
	offset := p.ip4Next
	p.ip4Next++
	if p.ip4Next >= p.ip4Size {
		p.ip4Next = p.ip4Start // wrap around
	}

	base := p.ip4Base.As4()
	val := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	val += offset

	return netip.AddrFrom4([4]byte{
		byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val),
	})
}

// nextIPv6 allocates the next IPv6 from the pool (caller must hold mu).
func (p *FakeIPPool) nextIPv6() netip.Addr {
	offset := p.ip6Next
	p.ip6Next++
	if p.ip6Next >= p.ip6Size {
		p.ip6Next = p.ip6Start
	}

	b := p.ip6Base.As16()
	// Use the last 2 bytes for the offset
	binary.BigEndian.PutUint16(b[14:16], offset)
	return netip.AddrFrom16(b)
}

// BuildDNSResponse constructs a minimal DNS response for a given query with a fake IP.
// Supports A (IPv4) and AAAA (IPv6) queries. Returns nil for unsupported qtypes.
// The response has TTL=1 so that apps re-query soon (keeping mappings fresh).
func BuildDNSResponse(query []byte, fakeIPv4 netip.Addr, fakeIPv6 netip.Addr) []byte {
	if len(query) < 12 {
		return nil
	}

	// Parse QTYPE from the query
	// DNS format: Header(12) + QNAME(variable) + QTYPE(2) + QCLASS(2)
	qnameEnd := 12
	for qnameEnd < len(query) {
		labelLen := int(query[qnameEnd])
		if labelLen == 0 {
			qnameEnd++ // skip the terminating zero
			break
		}
		qnameEnd += 1 + labelLen
	}

	if qnameEnd+4 > len(query) {
		return nil
	}

	qtype := binary.BigEndian.Uint16(query[qnameEnd : qnameEnd+2])
	// qclass := binary.BigEndian.Uint16(query[qnameEnd+2 : qnameEnd+4])

	var answerIP []byte
	var rrType uint16

	switch qtype {
	case 1: // A record (IPv4)
		if !fakeIPv4.IsValid() {
			return nil
		}
		ip4 := fakeIPv4.As4()
		answerIP = ip4[:]
		rrType = 1
	case 28: // AAAA record (IPv6)
		if !fakeIPv6.IsValid() {
			return nil
		}
		ip6 := fakeIPv6.As16()
		answerIP = ip6[:]
		rrType = 28
	default:
		// For other qtypes (MX, TXT, SRV, etc.), return NXDOMAIN-like empty response
		return buildEmptyResponse(query, qnameEnd+4)
	}

	// Build response:
	// Header (12 bytes) + Question section (copy from query) + Answer RR
	questionLen := qnameEnd + 4 - 12 // QNAME + QTYPE + QCLASS
	answerLen := 2 + 2 + 2 + 4 + 2 + len(answerIP) // Name(ptr) + Type + Class + TTL + RDLen + RData

	resp := make([]byte, 12+questionLen+answerLen)

	// Header
	resp[0] = query[0] // Transaction ID
	resp[1] = query[1]
	resp[2] = 0x81 // QR=1, Opcode=0, AA=0, TC=0, RD=1
	resp[3] = 0x80 // RA=1, Z=0, RCODE=0 (No error)
	binary.BigEndian.PutUint16(resp[4:6], 1)   // QDCOUNT = 1
	binary.BigEndian.PutUint16(resp[6:8], 1)   // ANCOUNT = 1
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT = 0
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT = 0

	// Question section (copy from query)
	copy(resp[12:12+questionLen], query[12:12+questionLen])

	// Answer section
	off := 12 + questionLen
	resp[off] = 0xc0 // Name pointer to offset 12 (QNAME in question)
	resp[off+1] = 0x0c
	off += 2
	binary.BigEndian.PutUint16(resp[off:off+2], rrType) // TYPE
	off += 2
	binary.BigEndian.PutUint16(resp[off:off+2], 1) // CLASS = IN
	off += 2
	binary.BigEndian.PutUint32(resp[off:off+4], 1) // TTL = 1 second
	off += 4
	binary.BigEndian.PutUint16(resp[off:off+2], uint16(len(answerIP))) // RDLENGTH
	off += 2
	copy(resp[off:], answerIP)

	return resp
}

// buildEmptyResponse creates a DNS response with no answer records (for unsupported qtypes).
func buildEmptyResponse(query []byte, questionEnd int) []byte {
	questionLen := questionEnd - 12
	resp := make([]byte, 12+questionLen)

	resp[0] = query[0]
	resp[1] = query[1]
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x80 // RA=1, RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1
	// ANCOUNT, NSCOUNT, ARCOUNT = 0

	copy(resp[12:], query[12:questionEnd])
	return resp
}

// ParseDNSName extracts the queried domain name from a DNS query packet.
// Returns the domain in dotted notation, e.g. "google.com".
func ParseDNSName(query []byte) string {
	if len(query) < 13 {
		return ""
	}

	var name []byte
	off := 12 // skip DNS header
	for off < len(query) {
		labelLen := int(query[off])
		if labelLen == 0 {
			break
		}
		off++
		if off+labelLen > len(query) {
			return ""
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, query[off:off+labelLen]...)
		off += labelLen
	}
	return string(name)
}
