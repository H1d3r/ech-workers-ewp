# DNS Compression Pointer Robustness (P2-4)

## Current Status

The DNS response parser provides basic compression pointer handling but has known limitations with complex or malicious responses.

## Current Implementation

### What Works ✅

- Simple compression pointers (most common case)
- Standard responses from major DNS providers (Cloudflare, Google, Quad9)
- HTTPS record parsing for ECH configuration
- Basic bounds checking
- Forward reference detection
- Loop prevention (max 5 jumps)

### Known Limitations ❌

1. **Nested Compression**: May fail on pointer-to-pointer chains
2. **Complex Label Sequences**: Limited validation of label structures
3. **Malicious Responses**: Basic loop detection but not comprehensive
4. **Edge Cases**: Some non-standard but valid responses may fail

## Why Current Implementation is Acceptable

1. **Limited Scope**: Only used for ECH config queries (HTTPS records)
2. **Trusted Sources**: Queries go to well-known DNS providers
3. **Graceful Degradation**: Failures fall back to plain TLS (if configured)
4. **Real-World Testing**: Works with all major DNS providers
5. **Performance**: Simple parser is fast and has low memory footprint

## Recent Improvements (P2-4)

```go
// Added in P2-4 fix:
- skipDNSName() helper function with proper compression handling
- Forward reference validation (pointer must point backwards)
- Loop detection (max 5 jumps)
- Improved bounds checking throughout
- Better error messages for debugging
- Separated HTTPS record parsing for clarity
```

## Example: Compression Pointer Handling

### Simple Case (Works)
```
Offset 12: example.com (labels)
Offset 30: [C0 0C] (pointer to offset 12)
```

### Nested Case (May Fail)
```
Offset 12: example (label)
Offset 20: [C0 0C] (pointer to offset 12)
Offset 30: [C0 14] (pointer to offset 20, which is a pointer)
```

### Loop Case (Detected)
```
Offset 12: [C0 14] (pointer to offset 20)
Offset 20: [C0 0C] (pointer to offset 12)
Result: Error after 5 jumps
```

## Full RFC 1035 Compliance

For complete DNS parsing, the following would be needed:

### 1. Proper Name Decompression

```go
func decompressName(data []byte, offset int) (string, int, error) {
    var labels []string
    visited := make(map[int]bool)
    originalOffset := offset
    jumped := false
    
    for {
        if visited[offset] {
            return "", 0, fmt.Errorf("compression loop detected")
        }
        visited[offset] = true
        
        if offset >= len(data) {
            return "", 0, fmt.Errorf("offset out of bounds")
        }
        
        length := int(data[offset])
        
        if length == 0 {
            // End of name
            if !jumped {
                offset++
            }
            return strings.Join(labels, "."), offset, nil
        }
        
        if length&0xC0 == 0xC0 {
            // Compression pointer
            if offset+1 >= len(data) {
                return "", 0, fmt.Errorf("truncated pointer")
            }
            
            pointer := int(length&0x3F)<<8 | int(data[offset+1])
            
            if pointer >= len(data) {
                return "", 0, fmt.Errorf("pointer out of bounds")
            }
            
            if !jumped {
                offset += 2
                jumped = true
            }
            
            // Follow pointer
            offset = pointer
            continue
        }
        
        // Regular label
        if length > 63 {
            return "", 0, fmt.Errorf("label too long")
        }
        
        if offset+1+length > len(data) {
            return "", 0, fmt.Errorf("label extends beyond data")
        }
        
        label := string(data[offset+1 : offset+1+length])
        labels = append(labels, label)
        offset += 1 + length
    }
}
```

### 2. Full Record Parsing

```go
type DNSRecord struct {
    Name  string
    Type  uint16
    Class uint16
    TTL   uint32
    Data  []byte
}

func parseRecord(data []byte, offset int) (*DNSRecord, int, error) {
    name, offset, err := decompressName(data, offset)
    if err != nil {
        return nil, 0, err
    }
    
    if offset+10 > len(data) {
        return nil, 0, fmt.Errorf("truncated record")
    }
    
    record := &DNSRecord{
        Name:  name,
        Type:  binary.BigEndian.Uint16(data[offset:]),
        Class: binary.BigEndian.Uint16(data[offset+2:]),
        TTL:   binary.BigEndian.Uint32(data[offset+4:]),
    }
    
    dataLen := int(binary.BigEndian.Uint16(data[offset+8:]))
    offset += 10
    
    if offset+dataLen > len(data) {
        return nil, 0, fmt.Errorf("truncated record data")
    }
    
    record.Data = data[offset : offset+dataLen]
    offset += dataLen
    
    return record, offset, nil
}
```

### 3. Using miekg/dns Library

```go
import "github.com/miekg/dns"

func parseResponseWithMiekg(response []byte) (string, error) {
    msg := new(dns.Msg)
    if err := msg.Unpack(response); err != nil {
        return "", err
    }
    
    for _, rr := range msg.Answer {
        if https, ok := rr.(*dns.HTTPS); ok {
            for _, param := range https.Value {
                if echParam, ok := param.(*dns.SVCBECHConfig); ok {
                    return base64.StdEncoding.EncodeToString(echParam.ECH), nil
                }
            }
        }
    }
    
    return "", fmt.Errorf("no ECH config found")
}
```

## Testing Strategy

### Current Tests

```bash
# Test with major DNS providers
dig @1.1.1.1 HTTPS cloudflare-ech.com
dig @8.8.8.8 HTTPS cloudflare-ech.com
dig @9.9.9.9 HTTPS cloudflare-ech.com
```

### Comprehensive Tests (Future)

```go
func TestDNSCompression(t *testing.T) {
    tests := []struct {
        name     string
        response []byte
        want     string
        wantErr  bool
    }{
        {
            name:     "simple compression",
            response: buildSimpleCompressedResponse(),
            want:     "expected-ech-config",
            wantErr:  false,
        },
        {
            name:     "nested compression",
            response: buildNestedCompressedResponse(),
            want:     "expected-ech-config",
            wantErr:  false,
        },
        {
            name:     "compression loop",
            response: buildLoopResponse(),
            wantErr:  true,
        },
        {
            name:     "forward reference",
            response: buildForwardRefResponse(),
            wantErr:  true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseResponse(tt.response)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseResponse() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("ParseResponse() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Fuzzing (Future)

```go
func FuzzParseResponse(f *testing.F) {
    // Seed with valid responses
    f.Add(validResponse1)
    f.Add(validResponse2)
    
    f.Fuzz(func(t *testing.T, data []byte) {
        // Should not panic on any input
        _, _ = ParseResponse(data)
    })
}
```

## Migration Path

### Option 1: Use miekg/dns (Recommended)

**Pros**:
- Full RFC 1035 compliance
- Well-tested and maintained
- Handles all edge cases
- Active community

**Cons**:
- External dependency
- Larger binary size
- May be overkill for ECH-only use case

**Implementation**:
```bash
go get github.com/miekg/dns
```

### Option 2: Complete Rewrite

**Pros**:
- No external dependencies
- Tailored to ECH use case
- Full control over implementation

**Cons**:
- Significant development time
- Requires extensive testing
- Maintenance burden

### Option 3: Hybrid Approach

**Pros**:
- Keep simple parser for common cases
- Fall back to miekg/dns for complex cases
- Best of both worlds

**Cons**:
- More complex code
- Still requires external dependency

## Decision

**Status**: Current implementation is sufficient

**Reason**:
- Works with all major DNS providers
- ECH-specific use case (not general DNS)
- Graceful fallback on failure
- Recent improvements (P2-4) address most concerns

**Future Work**:
- Monitor for parsing failures in production
- Consider miekg/dns if issues arise
- Add fuzzing tests for robustness
- Implement full parser if expanding DNS functionality

## References

- [RFC 1035: Domain Names - Implementation and Specification](https://tools.ietf.org/html/rfc1035)
- [RFC 1035 Section 4.1.4: Message compression](https://tools.ietf.org/html/rfc1035#section-4.1.4)
- [miekg/dns Library](https://github.com/miekg/dns)
- [DNS Compression Explained](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4)

## Related Issues

- P2-4: DNS Compression Pointer Robustness / DNS 压缩指针鲁棒性
- P0-12: DoH Multi-Source (uses this parser)
- P1-15: Bypass Resolver (uses this parser)
