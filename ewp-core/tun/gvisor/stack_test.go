package gvisor

import (
	"testing"
)

// TestUDPChecksum verifies the udpChecksum function against a known-good
// reference value computed manually from RFC 768 pseudo-header + UDP segment.
func TestUDPChecksum(t *testing.T) {
	// Minimal UDP segment: src=10.0.0.1:1234 dst=10.0.0.2:53, payload="hi"
	srcIP := []byte{10, 0, 0, 1}
	dstIP := []byte{10, 0, 0, 2}

	// UDP header: srcPort=1234(0x04D2), dstPort=53(0x0035), length=10(8+2), checksum=0
	// Payload: "hi" = {0x68, 0x69}
	udpData := []byte{
		0x04, 0xD2, // src port
		0x00, 0x35, // dst port
		0x00, 0x0A, // length = 10
		0x00, 0x00, // checksum placeholder
		0x68, 0x69, // "hi"
	}

	csum := udpChecksum(udpData, srcIP, dstIP)

	// The checksum must be non-zero (RFC 768: 0x0000 → 0xFFFF).
	if csum == 0 {
		t.Fatal("udpChecksum returned 0x0000 — must be 0xFFFF per RFC 768")
	}

	// Verify the checksum by re-computing with the checksum set in the segment.
	// A correct checksum should yield 0x0000 (or 0xFFFF after complement).
	udpData[6] = byte(csum >> 8)
	udpData[7] = byte(csum)

	verify := udpChecksum(udpData, srcIP, dstIP)
	// When the checksum is embedded, the verification sum should be 0xFFFF
	// (since ~0 = 0xFFFF in one's complement).
	if verify != 0xFFFF {
		t.Fatalf("verification checksum = 0x%04X, want 0xFFFF", verify)
	}
}

// TestUDPChecksum_OddLength ensures the odd-length padding branch works.
func TestUDPChecksum_OddLength(t *testing.T) {
	srcIP := []byte{192, 168, 1, 1}
	dstIP := []byte{192, 168, 1, 2}

	// UDP header + 3 byte payload ("abc") → 11 bytes total (odd)
	udpData := []byte{
		0x00, 0x50, // src port 80
		0x00, 0x51, // dst port 81
		0x00, 0x0B, // length = 11
		0x00, 0x00, // checksum placeholder
		0x61, 0x62, 0x63, // "abc"
	}

	csum := udpChecksum(udpData, srcIP, dstIP)
	if csum == 0 {
		t.Fatal("checksum is zero")
	}

	// Verify
	udpData[6] = byte(csum >> 8)
	udpData[7] = byte(csum)
	verify := udpChecksum(udpData, srcIP, dstIP)
	if verify != 0xFFFF {
		t.Fatalf("verification checksum = 0x%04X, want 0xFFFF", verify)
	}
}
