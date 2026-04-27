// Package stun is a tiny RFC 8489 STUN client used by the server to
// discover its own externally-observable IP and port for inclusion
// in v2 UDP_PROBE_RESP frames.
//
// It implements only the Binding request/response (the bare minimum
// for "what does the world see me as"). RFC 5780 NAT-behaviour
// discovery is intentionally NOT implemented: that requires multiple
// STUN servers and per-test sockets, which is heavier than what we
// need here. Clients that want full NAT-type inference can do their
// own RFC 5780 dance from inside the v2 tunnel — they have all the
// frame types they need.
package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Reflexive holds the publicly-observable address as reported by a
// STUN binding response.
type Reflexive struct {
	IP   netip.Addr
	Port uint16
	From string // STUN server URL that returned this answer
}

// DefaultServers is a small list of well-known public STUN servers.
// We avoid Google's stun.l.google.com because in some environments
// it's blocked; mixing CDN + telco + community servers gives the
// best chance of one working.
var DefaultServers = []string{
	"stun.cloudflare.com:3478",
	"stun.miwifi.com:3478",
	"global.stun.twilio.com:3478",
	"stun.nextcloud.com:443",
}

// Discover races N STUN servers and returns the first successful
// reflexive address. Returns (Reflexive{}, ctx.Err()) on timeout
// and (Reflexive{}, error) when every server failed.
//
// The supplied LocalAddr (may be empty) controls which local socket
// the request is sent from; pass the same address that ewpserver
// will receive UDP traffic on, otherwise the public mapping you
// observe will be unrelated to the mapping clients will see.
func Discover(ctx context.Context, servers []string, localAddr string) (Reflexive, error) {
	if len(servers) == 0 {
		servers = DefaultServers
	}

	type res struct {
		ref Reflexive
		err error
	}
	ch := make(chan res, len(servers))
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			r, err := query(ctx, s, localAddr)
			select {
			case ch <- res{r, err}:
			case <-ctx.Done():
			}
		}(srv)
	}
	go func() { wg.Wait(); close(ch) }()

	var lastErr error
	for r := range ch {
		if r.err == nil && r.ref.IP.IsValid() {
			return r.ref, nil
		}
		lastErr = r.err
	}
	if lastErr == nil {
		lastErr = errors.New("stun: no servers responded")
	}
	return Reflexive{}, lastErr
}

// query sends one Binding request to server and waits for the
// response. localAddr is optional ("" = OS picks); if set, the UDP
// socket binds to it.
func query(ctx context.Context, server, localAddr string) (Reflexive, error) {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(2 * time.Second)
	}

	var laddr *net.UDPAddr
	if localAddr != "" {
		var err error
		laddr, err = net.ResolveUDPAddr("udp", localAddr)
		if err != nil {
			return Reflexive{}, fmt.Errorf("stun: bad local addr %q: %w", localAddr, err)
		}
	}
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return Reflexive{}, fmt.Errorf("stun: resolve %q: %w", server, err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return Reflexive{}, fmt.Errorf("stun: listen: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	tx, msg := buildBindingRequest()
	if _, err := conn.WriteTo(msg, raddr); err != nil {
		return Reflexive{}, fmt.Errorf("stun: write: %w", err)
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return Reflexive{}, fmt.Errorf("stun: read: %w", err)
		}
		ref, ok := parseBindingResponse(buf[:n], tx)
		if !ok {
			continue // unrelated packet; keep reading until deadline
		}
		ref.From = server
		return ref, nil
	}
}

// ----------------------------------------------------------------------
// Wire encode / decode (RFC 8489)
// ----------------------------------------------------------------------

const (
	stunMagicCookie = 0x2112A442
	msgBindingReq   = 0x0001
	msgBindingResp  = 0x0101
	attrXorMappedAd = 0x0020 // XOR-MAPPED-ADDRESS
	attrMappedAddr  = 0x0001 // MAPPED-ADDRESS (legacy)
)

// buildBindingRequest returns the 96-bit transaction ID and the
// 20-byte Binding-Request message.
func buildBindingRequest() ([12]byte, []byte) {
	var tx [12]byte
	_, _ = rand.Read(tx[:])
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], msgBindingReq)
	binary.BigEndian.PutUint16(msg[2:4], 0) // length = 0 attrs
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], tx[:])
	return tx, msg
}

// parseBindingResponse extracts the reflexive address from a STUN
// Binding response. Returns (zero, false) if the packet is not a
// matching response or doesn't contain (X)MAPPED-ADDRESS.
func parseBindingResponse(b []byte, wantTx [12]byte) (Reflexive, bool) {
	if len(b) < 20 {
		return Reflexive{}, false
	}
	if binary.BigEndian.Uint16(b[0:2]) != msgBindingResp {
		return Reflexive{}, false
	}
	attrLen := int(binary.BigEndian.Uint16(b[2:4]))
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return Reflexive{}, false
	}
	var tx [12]byte
	copy(tx[:], b[8:20])
	if tx != wantTx {
		return Reflexive{}, false
	}
	if 20+attrLen > len(b) {
		return Reflexive{}, false
	}

	// Walk attributes. Prefer XOR-MAPPED-ADDRESS.
	off := 20
	end := 20 + attrLen
	var fallback Reflexive
	for off+4 <= end {
		atype := binary.BigEndian.Uint16(b[off : off+2])
		alen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+alen > end {
			break
		}
		val := b[off : off+alen]
		off += (alen + 3) &^ 3 // 4-byte align

		switch atype {
		case attrXorMappedAd:
			if r, ok := parseXorMapped(val, b); ok {
				return r, true
			}
		case attrMappedAddr:
			if r, ok := parseMapped(val); ok {
				fallback = r
			}
		}
	}
	if fallback.IP.IsValid() {
		return fallback, true
	}
	return Reflexive{}, false
}

func parseXorMapped(v, full []byte) (Reflexive, bool) {
	if len(v) < 4 {
		return Reflexive{}, false
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4]) ^ uint16(stunMagicCookie>>16)
	switch family {
	case 0x01: // IPv4
		if len(v) < 8 {
			return Reflexive{}, false
		}
		var arr [4]byte
		cookie := binary.BigEndian.Uint32(full[4:8])
		x := binary.BigEndian.Uint32(v[4:8]) ^ cookie
		binary.BigEndian.PutUint32(arr[:], x)
		return Reflexive{IP: netip.AddrFrom4(arr), Port: port}, true
	case 0x02: // IPv6
		if len(v) < 20 {
			return Reflexive{}, false
		}
		var arr [16]byte
		// Cookie || Tx
		key := make([]byte, 16)
		copy(key, full[4:20])
		for i := 0; i < 16; i++ {
			arr[i] = v[4+i] ^ key[i]
		}
		return Reflexive{IP: netip.AddrFrom16(arr), Port: port}, true
	}
	return Reflexive{}, false
}

func parseMapped(v []byte) (Reflexive, bool) {
	if len(v) < 4 {
		return Reflexive{}, false
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4])
	switch family {
	case 0x01:
		if len(v) < 8 {
			return Reflexive{}, false
		}
		var arr [4]byte
		copy(arr[:], v[4:8])
		return Reflexive{IP: netip.AddrFrom4(arr), Port: port}, true
	case 0x02:
		if len(v) < 20 {
			return Reflexive{}, false
		}
		var arr [16]byte
		copy(arr[:], v[4:20])
		return Reflexive{IP: netip.AddrFrom16(arr), Port: port}, true
	}
	return Reflexive{}, false
}
