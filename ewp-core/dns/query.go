package dns

import "encoding/binary"

// BuildQuery builds a DNS query message for the given domain and record type
func BuildQuery(domain string, qtype uint16) []byte {
	var query []byte

	// DNS Header (12 bytes)
	query = append(query, 0x00, 0x01) // Transaction ID
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
