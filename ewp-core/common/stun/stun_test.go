package stun

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestDiscover_LoopbackServer spins up an in-process STUN server on a
// random local port and verifies the client correctly extracts the
// XOR-MAPPED-ADDRESS reply.
func TestDiscover_LoopbackServer(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go fakeSTUN(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ref, err := Discover(ctx, []string{ln.LocalAddr().String()}, "")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !ref.IP.IsLoopback() {
		t.Errorf("ip = %s, want loopback", ref.IP)
	}
	if ref.Port == 0 {
		t.Error("port = 0")
	}
	if ref.From == "" {
		t.Error("From not set")
	}
}

// TestDiscover_AllFail asserts that with only unreachable servers,
// Discover returns an error within the deadline rather than hanging.
func TestDiscover_AllFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_, err := Discover(ctx, []string{"127.0.0.1:1"}, "")
	if err == nil {
		t.Fatal("expected error from unreachable server")
	}
}

// fakeSTUN reads one Binding request and writes a corresponding
// Binding response with XOR-MAPPED-ADDRESS = the client's actual
// (loopback IP, source port).
func fakeSTUN(ln *net.UDPConn) {
	buf := make([]byte, 1500)
	n, src, err := ln.ReadFromUDPAddrPort(buf)
	if err != nil {
		return
	}
	if n < 20 {
		return
	}
	var tx [12]byte
	copy(tx[:], buf[8:20])

	// Build XOR-MAPPED-ADDRESS attribute (IPv4 only for the test).
	v := make([]byte, 8)
	v[0] = 0
	v[1] = 0x01 // IPv4
	xorPort := src.Port() ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(v[2:4], xorPort)
	ip4 := src.Addr().As4()
	cookie := uint32(stunMagicCookie)
	x := binary.BigEndian.Uint32(ip4[:]) ^ cookie
	binary.BigEndian.PutUint32(v[4:8], x)

	resp := make([]byte, 20+4+8)
	binary.BigEndian.PutUint16(resp[0:2], msgBindingResp)
	binary.BigEndian.PutUint16(resp[2:4], uint16(4+8))
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], tx[:])
	binary.BigEndian.PutUint16(resp[20:22], attrXorMappedAd)
	binary.BigEndian.PutUint16(resp[22:24], uint16(len(v)))
	copy(resp[24:], v)

	_, _ = ln.WriteToUDPAddrPort(resp, src)
}
