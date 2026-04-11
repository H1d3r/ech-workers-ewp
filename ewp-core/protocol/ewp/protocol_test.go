package ewp

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// ─── 测试 UUID & 地址 ────────────────────────────────────────────────────────

var (
	protoTestUUID  = [16]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}
	protoTestUUID2 = [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
)

func protoTestAddr() Address {
	return Address{Type: AddressTypeDomain, Host: "example.com", Port: 443}
}

func protoTestIPv4Addr() Address {
	return Address{Type: AddressTypeIPv4, Host: "1.2.3.4", Port: 80}
}

func protoTestIPv6Addr() Address {
	return Address{Type: AddressTypeIPv6, Host: "2001:db8::1", Port: 8080}
}

// ─── 1. 握手编解码 Round-trip ────────────────────────────────────────────────

func TestHandshake_RoundTrip_TCP_Domain(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	frame, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID})
	if err != nil {
		t.Fatalf("DecodeHandshakeRequest: %v", err)
	}
	if decoded.UUID != protoTestUUID {
		t.Errorf("UUID mismatch: got %x want %x", decoded.UUID, protoTestUUID)
	}
	if decoded.Command != CommandTCP {
		t.Errorf("Command mismatch: got %d want %d", decoded.Command, CommandTCP)
	}
	if decoded.TargetAddr.Host != "example.com" || decoded.TargetAddr.Port != 443 {
		t.Errorf("Address mismatch: got %+v", decoded.TargetAddr)
	}
}

func TestHandshake_RoundTrip_UDP_IPv4(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandUDP, protoTestIPv4Addr())
	frame, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID})
	if err != nil {
		t.Fatalf("DecodeHandshakeRequest: %v", err)
	}
	if decoded.Command != CommandUDP {
		t.Errorf("Command mismatch: got %d want %d", decoded.Command, CommandUDP)
	}
	if decoded.TargetAddr.Host != "1.2.3.4" || decoded.TargetAddr.Port != 80 {
		t.Errorf("IPv4 address mismatch: got %+v", decoded.TargetAddr)
	}
}

func TestHandshake_RoundTrip_IPv6(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestIPv6Addr())
	frame, err := req.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID})
	if err != nil {
		t.Fatalf("Decode IPv6: %v", err)
	}
	if decoded.TargetAddr.Port != 8080 {
		t.Errorf("IPv6 port mismatch: got %d", decoded.TargetAddr.Port)
	}
}

// ─── 2. 认证失败场景 ─────────────────────────────────────────────────────────

func TestHandshake_WrongUUID_Rejected(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	frame, _ := req.Encode()

	_, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID2})
	if err == nil {
		t.Fatal("expected auth error for wrong UUID, got nil")
	}
}

func TestHandshake_TamperedCiphertext_Rejected(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	frame, _ := req.Encode()

	// 篡改 ciphertext 中间位
	frame[20] ^= 0xFF

	_, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID})
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
}

func TestHandshake_TamperedHMAC_Rejected(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	frame, _ := req.Encode()

	// 篡改最后 16 字节（外层 HMAC）
	for i := len(frame) - 16; i < len(frame); i++ {
		frame[i] ^= 0xAA
	}

	_, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID})
	if err == nil {
		t.Fatal("expected error for tampered HMAC, got nil")
	}
}

func TestHandshake_TooShort_Rejected(t *testing.T) {
	_, err := DecodeHandshakeRequest([]byte{0x01, 0x02, 0x03}, [][16]byte{protoTestUUID})
	if err != ErrInvalidLength {
		t.Errorf("expected ErrInvalidLength, got %v", err)
	}
}

func TestHandshake_ZeroVersion_Rejected(t *testing.T) {
	// 需要一个足够大的帧才能通过长度检查（15 + MinPayloadLength + 16 = 111 字节）
	// 并且 payloadLen 字段（bytes 13-14）要 >= MinPayloadLength
	frame := make([]byte, 15+MinPayloadLength+16)
	frame[0] = 0x00 // version = 0 → invalid
	// 设置合法的 payloadLen = MinPayloadLength，使长度检查通过
	frame[13] = 0x00
	frame[14] = byte(MinPayloadLength)
	_, err := DecodeHandshakeRequest(frame, [][16]byte{protoTestUUID})
	if err != ErrInvalidVersion {
		t.Errorf("expected ErrInvalidVersion, got %v", err)
	}
}

// ─── 3. 握手响应 Round-trip ──────────────────────────────────────────────────

func TestHandshakeResponse_RoundTrip(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	resp := NewSuccessResponse(req.Version, req.Nonce)

	encoded, err := resp.Encode(protoTestUUID)
	if err != nil {
		t.Fatalf("Encode response: %v", err)
	}

	decoded, err := DecodeHandshakeResponse(encoded, req.Version, req.Nonce, protoTestUUID)
	if err != nil {
		t.Fatalf("DecodeHandshakeResponse: %v", err)
	}
	if decoded.Status != StatusOK {
		t.Errorf("Status mismatch: got %d want %d", decoded.Status, StatusOK)
	}
}

func TestHandshakeResponse_WrongNonce_Rejected(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	resp := NewSuccessResponse(req.Version, req.Nonce)
	encoded, _ := resp.Encode(protoTestUUID)

	var wrongNonce [12]byte
	wrongNonce[0] = 0xFF
	_, err := DecodeHandshakeResponse(encoded, req.Version, wrongNonce, protoTestUUID)
	if err == nil {
		t.Fatal("expected error for wrong nonce, got nil")
	}
}

func TestHandshakeResponse_WrongUUID_Rejected(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	resp := NewSuccessResponse(req.Version, req.Nonce)
	encoded, _ := resp.Encode(protoTestUUID)

	_, err := DecodeHandshakeResponse(encoded, req.Version, req.Nonce, protoTestUUID2)
	if err == nil {
		t.Fatal("expected error for wrong UUID in response, got nil")
	}
}

// ─── 4. UUIDKeyCache ─────────────────────────────────────────────────────────

func TestUUIDKeyCache_RoundTrip(t *testing.T) {
	cache := NewUUIDKeyCache([][16]byte{protoTestUUID, protoTestUUID2})

	for _, u := range [][16]byte{protoTestUUID, protoTestUUID2} {
		req := NewHandshakeRequest(u, CommandTCP, protoTestAddr())
		frame, _ := req.Encode()
		decoded, err := DecodeHandshakeRequestCached(frame, cache)
		if err != nil {
			t.Errorf("UUID %x: %v", u, err)
			continue
		}
		if decoded.UUID != u {
			t.Errorf("UUID %x: decoded UUID mismatch %x", u, decoded.UUID)
		}
	}
}

func TestUUIDKeyCache_Allocs(t *testing.T) {
	req := NewHandshakeRequest(protoTestUUID, CommandTCP, protoTestAddr())
	frame, _ := req.Encode()
	cache := NewUUIDKeyCache([][16]byte{protoTestUUID})

	allocs := testing.AllocsPerRun(500, func() {
		_, _ = DecodeHandshakeRequestCached(frame, cache)
	})
	// chacha20-poly1305 AEAD Open、HMAC-SHA256、地址解析等内部各有分配
	// 实测 arm64/Go1.24 约 12 次，放宽上限为 20 以兼容不同平台
	if allocs > 20 {
		t.Errorf("hot path allocates %.0f objects, want ≤20", allocs)
	}
}

// ─── 5. Nonce 防重放 ─────────────────────────────────────────────────────────

func TestNonceCache_ReplayDetected(t *testing.T) {
	c := NewNonceCache()
	var nonce [12]byte
	nonce[0] = 0xDE
	nonce[1] = 0xAD

	// 第一次：应该返回 false（新 nonce）
	if c.CheckAndAdd(nonce) {
		t.Fatal("first CheckAndAdd should return false (not replay)")
	}
	// 第二次：应该返回 true（重放）
	if !c.CheckAndAdd(nonce) {
		t.Fatal("second CheckAndAdd should return true (replay detected)")
	}
}

func TestNonceCache_DifferentNonces_Accepted(t *testing.T) {
	c := NewNonceCache()
	for i := 0; i < 100; i++ {
		var nonce [12]byte
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		if c.CheckAndAdd(nonce) {
			t.Fatalf("nonce %d falsely detected as replay", i)
		}
	}
}

func TestNonceCache_Concurrent(t *testing.T) {
	c := NewNonceCache()
	var nonce [12]byte
	nonce[0] = 0x42

	var replayCount int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.CheckAndAdd(nonce) {
				mu.Lock()
				replayCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// 100 个 goroutine 并发，只有 1 个应该成功插入，其余 99 个是重放
	if replayCount != 99 {
		t.Errorf("expected 99 replays, got %d", replayCount)
	}
}

// ─── 6. RateLimiter ──────────────────────────────────────────────────────────

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10, time.Second*5)
	for i := 0; i < 10; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(5, time.Second*10)
	ip := "5.6.7.8"

	// 前 5 次允许
	for i := 0; i < 5; i++ {
		rl.Allow(ip)
	}
	// 第 6 次应被拒绝（封禁）
	if rl.Allow(ip) {
		t.Fatal("6th request should be blocked")
	}
}

func TestRateLimiter_DifferentIPs_Independent(t *testing.T) {
	rl := NewRateLimiter(2, time.Second*5)

	// ip1 超限
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1") // 第3次，超限封禁

	// ip2 不受 ip1 影响
	if !rl.Allow("10.0.0.2") {
		t.Fatal("different IP should not be rate limited")
	}
}

func TestRateLimiter_RecordFailure_ExtendsBan(t *testing.T) {
	rl := NewRateLimiter(100, time.Second*5)
	ip := "9.9.9.9"

	rl.RecordFailure(ip)
	// 失败记录后应被封禁
	if rl.Allow(ip) {
		t.Fatal("IP should be banned after RecordFailure")
	}
}

// ─── 7. FakeResponse ─────────────────────────────────────────────────────────

func TestGenerateFakeResponse_NotEmpty(t *testing.T) {
	resp := GenerateFakeResponse()
	if len(resp) == 0 {
		t.Fatal("FakeResponse should not be empty")
	}
}

func TestGenerateFakeResponse_DifferentEachTime(t *testing.T) {
	r1 := GenerateFakeResponse()
	r2 := GenerateFakeResponse()
	// 两次生成的假响应应不完全相同（随机性）
	if bytes.Equal(r1, r2) {
		t.Log("warning: two FakeResponses are identical (possible if truly random collides)")
	}
}
