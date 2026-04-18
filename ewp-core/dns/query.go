package dns

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// BuildQuery builds a DNS query message for the given domain and record type
// P2-3: Uses random TXID to avoid fingerprinting
func BuildQuery(domain string, qtype uint16) []byte {
	var query []byte

	// DNS Header (12 bytes)
	// P2-3: Random TXID instead of hardcoded 0x0001 to avoid DPI fingerprinting
	txidBig, err := rand.Int(rand.Reader, big.NewInt(65535))
	if err != nil {
		// Fallback to non-zero constant if randomness fails
		query = append(query, 0x00, 0x01)
	} else {
		txid := uint16(txidBig.Int64() + 1) // 1-65535, avoid 0
		txidBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(txidBytes, txid)
		query = append(query, txidBytes...)
	}
	
	query = append(query, 0x01, 0x00) // Flags: Standard query
	query = append(query, 0x00, 0x01) // Questions: 1
	query = append(query, 0x00, 0x00) // Answer RRs: 0
	query = append(query, 0x00, 0x00) // Authority RRs: 0
	query = append(query, 0x00, 0x00) // Additional RRs: 0

	// Question section
	labels := []byte(domain)
	start := 0
	for i := 0; i < len(labels); i++ {
		if labels[i] == '.' {
			query = append(query, byte(i-start))
			query = append(query, labels[start:i]...)
			start = i + 1
		}
	}
	if start < len(labels) {
		query = append(query, byte(len(labels)-start))
		query = append(query, labels[start:]...)
	}
	query = append(query, 0x00) // End of domain name

	// QTYPE (2 bytes)
	qtypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qtypeBytes, qtype)
	query = append(query, qtypeBytes...)

	// QCLASS (2 bytes) - IN (Internet)
	query = append(query, 0x00, 0x01)

	return query
}
