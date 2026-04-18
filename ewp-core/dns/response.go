package dns

import (
	"encoding/base64"
	"fmt"
)

// P2-4: DNS Compression Pointer Robustness
//
// Current implementation provides basic DNS response parsing for ECH configuration.
// It handles simple compression pointers but may fail on:
// - Nested compression pointers (pointer to pointer)
// - Compression loops (malicious responses)
// - Complex label sequences
//
// This is acceptable because:
// 1. Only used for ECH config queries (HTTPS records)
// 2. Major DNS providers (Cloudflare, Google) return standard responses
// 3. Failures are gracefully handled (fallback to plain TLS if configured)
//
// For production-grade DNS parsing, consider:
// - github.com/miekg/dns (full RFC 1035 compliance)
// - Complete rewrite with proper state machine
//
// See DNS_COMPRESSION_TODO.md for details

// ParseResponse parses a DNS response and extracts ECH configuration from HTTPS record
// This is a simplified parser for ECH records
// 
// P2-4: Known limitations:
// - May fail on nested compression pointers
// - No loop detection for malicious responses
// - Limited validation of pointer offsets
func ParseResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("response too short")
	}

	// Parse DNS header
	answerCount := int(response[6])<<8 | int(response[7])
	if answerCount == 0 {
		return "", fmt.Errorf("no answers in response")
	}

	offset := 12

	// Skip question section
	// P2-4: Basic compression pointer handling
	offset, err := skipDNSName(response, offset)
	if err != nil {
		return "", fmt.Errorf("failed to skip question name: %w", err)
	}
	if offset+4 > len(response) {
		return "", fmt.Errorf("truncated question section")
	}
	offset += 4 // qtype(2) + qclass(2)

	// Parse answer section to find HTTPS record
	for i := 0; i < answerCount && offset < len(response); i++ {
		// Skip name (usually compressed pointer)
		// P2-4: Improved bounds checking
		offset, err = skipDNSName(response, offset)
		if err != nil {
			return "", fmt.Errorf("failed to skip answer name: %w", err)
		}

		if offset+10 > len(response) {
			return "", fmt.Errorf("truncated answer section")
		}

		recordType := uint16(response[offset])<<8 | uint16(response[offset+1])
		dataLen := int(response[offset+8])<<8 | int(response[offset+9])
		offset += 10

		if offset+dataLen > len(response) {
			return "", fmt.Errorf("truncated answer data")
		}

		// Check if this is an HTTPS record (Type 65)
		if recordType == 65 {
			echConfig, err := parseHTTPSRecord(response, offset, dataLen)
			if err == nil && echConfig != "" {
				return echConfig, nil
			}
		}

		offset += dataLen
	}

	return "", fmt.Errorf("no ECH parameter found in HTTPS record")
}

// P2-4: Helper function to skip DNS name with improved compression pointer handling
func skipDNSName(data []byte, offset int) (int, error) {
	const maxJumps = 5 // Prevent infinite loops from malicious responses
	jumps := 0
	
	for offset < len(data) {
		if data[offset] == 0 {
			return offset + 1, nil
		}
		
		// Check for compression pointer (top 2 bits set)
		if data[offset]&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return 0, fmt.Errorf("truncated compression pointer")
			}
			
			// P2-4: Validate pointer offset
			pointer := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			if pointer >= offset {
				return 0, fmt.Errorf("invalid compression pointer: forward reference")
			}
			if pointer >= len(data) {
				return 0, fmt.Errorf("invalid compression pointer: out of bounds")
			}
			
			// P2-4: Limit jumps to prevent loops
			jumps++
			if jumps > maxJumps {
				return 0, fmt.Errorf("too many compression pointer jumps (possible loop)")
			}
			
			return offset + 2, nil
		}
		
		// Regular label
		labelLen := int(data[offset])
		if labelLen > 63 {
			return 0, fmt.Errorf("invalid label length: %d", labelLen)
		}
		
		offset += labelLen + 1
		if offset > len(data) {
			return 0, fmt.Errorf("label extends beyond data")
		}
	}
	
	return 0, fmt.Errorf("unterminated DNS name")
}

// P2-4: Extract HTTPS record parsing into separate function for clarity
func parseHTTPSRecord(data []byte, offset, dataLen int) (string, error) {
	if dataLen < 3 {
		return "", fmt.Errorf("HTTPS record too short")
	}

	// Skip priority (2 bytes)
	dataOffset := offset + 2

	// Skip target name
	var err error
	dataOffset, err = skipDNSName(data, dataOffset)
	if err != nil {
		return "", fmt.Errorf("failed to skip target name: %w", err)
	}

	// Parse SvcParams to find ECH (key 5)
	endOffset := offset + dataLen
	for dataOffset+4 <= endOffset {
		if dataOffset+4 > len(data) {
			break
		}
		
		paramKey := uint16(data[dataOffset])<<8 | uint16(data[dataOffset+1])
		paramLen := uint16(data[dataOffset+2])<<8 | uint16(data[dataOffset+3])
		dataOffset += 4

		if dataOffset+int(paramLen) > endOffset || dataOffset+int(paramLen) > len(data) {
			return "", fmt.Errorf("SvcParam extends beyond record")
		}

		// ECH parameter key is 5
		if paramKey == 5 {
			echData := data[dataOffset : dataOffset+int(paramLen)]
			// Return base64 encoded ECH data
			return base64.StdEncoding.EncodeToString(echData), nil
		}

		dataOffset += int(paramLen)
	}

	return "", fmt.Errorf("no ECH parameter in HTTPS record")
}

// ParseAddressRecords parses A and AAAA records from DNS response
// Returns list of IP addresses (both IPv4 and IPv6)
func ParseAddressRecords(response []byte) ([]string, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse DNS header
	answerCount := int(response[6])<<8 | int(response[7])
	if answerCount == 0 {
		return nil, fmt.Errorf("no answers in response")
	}

	offset := 12

	// Skip question section
	offset, err := skipDNSName(response, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to skip question name: %w", err)
	}
	if offset+4 > len(response) {
		return nil, fmt.Errorf("truncated question section")
	}
	offset += 4 // qtype(2) + qclass(2)

	var addresses []string

	// Parse answer section
	for i := 0; i < answerCount && offset < len(response); i++ {
		// Skip name
		offset, err = skipDNSName(response, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to skip answer name: %w", err)
		}

		if offset+10 > len(response) {
			return nil, fmt.Errorf("truncated answer section")
		}

		recordType := uint16(response[offset])<<8 | uint16(response[offset+1])
		dataLen := int(response[offset+8])<<8 | int(response[offset+9])
		offset += 10

		if offset+dataLen > len(response) {
			return nil, fmt.Errorf("truncated answer data")
		}

		// Type A (1) - IPv4
		if recordType == 1 && dataLen == 4 {
			ip := fmt.Sprintf("%d.%d.%d.%d",
				response[offset], response[offset+1],
				response[offset+2], response[offset+3])
			addresses = append(addresses, ip)
		}

		// Type AAAA (28) - IPv6
		if recordType == 28 && dataLen == 16 {
			ip := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				response[offset], response[offset+1],
				response[offset+2], response[offset+3],
				response[offset+4], response[offset+5],
				response[offset+6], response[offset+7],
				response[offset+8], response[offset+9],
				response[offset+10], response[offset+11],
				response[offset+12], response[offset+13],
				response[offset+14], response[offset+15])
			addresses = append(addresses, ip)
		}

		offset += dataLen
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no A or AAAA records found")
	}

	return addresses, nil
}
