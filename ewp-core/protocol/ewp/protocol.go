package ewp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version1 = 0x01

	CommandTCP byte = 0x01
	CommandUDP byte = 0x02

	OptionMux            byte = 0x01
	OptionDataEncryption byte = 0x02

	MinPaddingLength = 64
	MaxPaddingLength = 255
	TimeWindow       = 120

	MinPayloadLength = 80  // min ciphertext = min plaintext(64) + Poly1305 tag(16)
	MaxPayloadLength = 768 // max ciphertext = max plaintext(~537) + tag(16) = ~553, rounded up
)

var (
	ErrInvalidVersion   = errors.New("ewp: invalid version")
	ErrInvalidLength    = errors.New("ewp: invalid payload length")
	ErrInvalidTimestamp = errors.New("ewp: timestamp out of window")
	ErrInvalidAuth      = errors.New("ewp: authentication failed")
	ErrInvalidAddress   = errors.New("ewp: invalid address")
	ErrDecryptFailed    = errors.New("ewp: decryption failed")
)

type HandshakeRequest struct {
	Version       byte
	Nonce         [12]byte
	Timestamp     uint32
	UUID          [16]byte
	Command       byte
	TargetAddr    Address
	Options       byte
	PaddingLength byte
}

type HandshakeResponse struct {
	VersionEcho byte
	Status      byte
	ServerTime  uint32
	NonceEcho   [12]byte
	AuthTag     [8]byte
}

const (
	StatusOK    byte = 0x00
	StatusError byte = 0x01
)

func NewHandshakeRequest(uuid [16]byte, command byte, addr Address) *HandshakeRequest {
	// Version and padding length are traffic-obfuscation fields only — they do not
	// need cryptographic randomness. FastIntn uses a pooled math/rand source and
	// eliminates two crypto/rand syscalls + two big.Int heap allocations per call.
	version := byte(FastIntn(255) + 1) // [1, 255]

	paddingRange := int(MaxPaddingLength) - int(MinPaddingLength) + 1
	paddingLen := byte(FastIntn(paddingRange) + int(MinPaddingLength))

	req := &HandshakeRequest{
		Version:       version,
		Timestamp:     uint32(time.Now().Unix()),
		UUID:          uuid,
		Command:       command,
		TargetAddr:    addr,
		Options:       0,
		PaddingLength: paddingLen,
	}
	// Nonce IS security-critical: keep crypto/rand.
	if _, err := rand.Read(req.Nonce[:]); err != nil {
		panic("ewp: crypto/rand failed: " + err.Error())
	}
	return req
}

func (r *HandshakeRequest) Encode() ([]byte, error) {
	// 编码地址
	addrBytes, err := r.TargetAddr.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode address: %w", err)
	}

	// 计算 Plaintext 长度: Timestamp(4) + UUID(16) + Command(1) + Addr + Options(1) + PadLen(1) + Padding
	plaintextLen := 4 + 16 + 1 + len(addrBytes) + 1 + 1 + int(r.PaddingLength)

	// 预分配完整缓冲区: AD(15) + Ciphertext(plaintext + 16-byte Poly1305 tag) + HMAC(16)
	totalLen := 15 + plaintextLen + 16 + 16
	buf := make([]byte, totalLen)

	// === 1. 构建 AD (Authenticated Data) ===
	buf[0] = r.Version
	copy(buf[1:13], r.Nonce[:])
	binary.BigEndian.PutUint16(buf[13:15], uint16(plaintextLen+16)) // ciphertext length = plaintext + Poly1305 tag
	ad := buf[:15]

	// === 2. 构建 Plaintext (先临时写入，后续原地加密) ===
	offset := 15
	binary.BigEndian.PutUint32(buf[offset:], r.Timestamp)
	offset += 4
	copy(buf[offset:], r.UUID[:])
	offset += 16
	buf[offset] = r.Command
	offset++
	copy(buf[offset:], addrBytes)
	offset += len(addrBytes)
	buf[offset] = r.Options
	offset++
	buf[offset] = r.PaddingLength
	offset++

	// 填充随机 Padding
	rand.Read(buf[offset : offset+int(r.PaddingLength)])
	offset += int(r.PaddingLength)

	// === 3. 加密 (ChaCha20-Poly1305) ===
	key := deriveEncryptionKey(r.UUID, r.Nonce)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Seal 会追加 16 字节 Poly1305 tag
	plaintext := buf[15 : 15+plaintextLen]
	ciphertext := aead.Seal(buf[15:15], r.Nonce[:], plaintext, ad)

	// === 4. 计算外层 HMAC (快速熔断器) ===
	authTag := computeHMAC(r.UUID, ad, ciphertext)
	copy(buf[15+len(ciphertext):], authTag)

	return buf, nil
}

func DecodeHandshakeRequest(data []byte, validUUIDs [][16]byte) (*HandshakeRequest, error) {
	if len(data) < 15+MinPayloadLength+16 {
		return nil, ErrInvalidLength
	}

	version := data[0]
	if version == 0 {
		return nil, ErrInvalidVersion
	}

	var nonce [12]byte
	copy(nonce[:], data[1:13])

	payloadLen := binary.BigEndian.Uint16(data[13:15])
	if payloadLen < MinPayloadLength || payloadLen > MaxPayloadLength {
		return nil, ErrInvalidLength
	}

	if len(data) < 15+int(payloadLen)+16 {
		return nil, ErrInvalidLength
	}

	ad := data[0:15]
	ciphertext := data[15 : 15+payloadLen]
	authTag := data[15+payloadLen : 15+payloadLen+16]

	for _, uuid := range validUUIDs {
		expectedTag := computeHMAC(uuid, ad, ciphertext)
		if !hmac.Equal(authTag, expectedTag) {
			continue
		}

		key := deriveEncryptionKey(uuid, nonce)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			continue
		}

		plaintext, err := aead.Open(nil, nonce[:], ciphertext, ad)
		if err != nil {
			continue
		}

		req := &HandshakeRequest{
			Version: version,
			Nonce:   nonce,
		}

		if len(plaintext) < 4+16+1+1+1+1 {
			continue
		}

		req.Timestamp = binary.BigEndian.Uint32(plaintext[0:4])
		copy(req.UUID[:], plaintext[4:20])
		req.Command = plaintext[20]

		now := time.Now().Unix()
		if math.Abs(float64(int64(req.Timestamp)-now)) > TimeWindow {
			return nil, ErrInvalidTimestamp
		}

		addr, addrLen, err := DecodeAddress(plaintext[21:])
		if err != nil {
			continue
		}
		req.TargetAddr = addr

		offset := 21 + addrLen
		if len(plaintext) < offset+2 {
			continue
		}

		req.Options = plaintext[offset]
		req.PaddingLength = plaintext[offset+1]

		return req, nil
	}

	return nil, ErrInvalidAuth
}

func (r *HandshakeResponse) Encode(uuid [16]byte) ([]byte, error) {
	// 预分配: VersionEcho(1) + Status(1) + ServerTime(4) + NonceEcho(12) + AuthTag(8) = 26 bytes
	buf := make([]byte, 26)

	buf[0] = r.VersionEcho
	buf[1] = r.Status
	binary.BigEndian.PutUint32(buf[2:6], r.ServerTime)
	copy(buf[6:18], r.NonceEcho[:])

	// 计算 HMAC (前 17 字节)
	tag := computeResponseHMAC(uuid, buf[:17])
	copy(r.AuthTag[:], tag[:8])
	copy(buf[18:26], r.AuthTag[:])

	return buf, nil
}

func DecodeHandshakeResponse(data []byte, expectedVersion byte, expectedNonce [12]byte, uuid [16]byte) (*HandshakeResponse, error) {
	if len(data) < 26 {
		return nil, ErrInvalidLength
	}

	resp := &HandshakeResponse{}
	resp.VersionEcho = data[0]
	resp.Status = data[1]
	resp.ServerTime = binary.BigEndian.Uint32(data[2:6])
	copy(resp.NonceEcho[:], data[6:18])
	copy(resp.AuthTag[:], data[18:26])

	if resp.VersionEcho != expectedVersion {
		return nil, ErrInvalidVersion
	}

	if !bytes.Equal(resp.NonceEcho[:], expectedNonce[:]) {
		return nil, ErrInvalidAuth
	}

	expectedTag := computeResponseHMAC(uuid, data[:17])
	if !bytes.Equal(resp.AuthTag[:], expectedTag[:8]) {
		return nil, ErrInvalidAuth
	}

	return resp, nil
}

func NewSuccessResponse(version byte, nonce [12]byte) *HandshakeResponse {
	return &HandshakeResponse{
		VersionEcho: version,
		Status:      StatusOK,
		ServerTime:  uint32(time.Now().Unix()),
		NonceEcho:   nonce,
	}
}

func GenerateFakeResponse() []byte {
	fake := make([]byte, 26)
	rand.Read(fake)
	return fake
}

func deriveEncryptionKey(uuid [16]byte, nonce [12]byte) []byte {
	h := sha256.New()
	h.Write(uuid[:])
	h.Write(nonce[:])
	h.Write([]byte("EWP-ENC-v1"))
	return h.Sum(nil)
}

func computeHMAC(uuid [16]byte, ad, ciphertext []byte) []byte {
	keyHash := sha256.Sum256(uuid[:])
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(ad)
	h.Write(ciphertext)
	sum := h.Sum(nil)
	return sum[:16]
}

func computeResponseHMAC(uuid [16]byte, msg []byte) []byte {
	keyHash := sha256.Sum256(uuid[:])
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(msg)
	return h.Sum(nil)
}

// HMACKeyCache maps each UUID to its precomputed sha256(uuid) HMAC key.
// Build once at startup via NewHMACKeyCache; pass to DecodeHandshakeRequestCached
// to eliminate per-request SHA-256 key derivation on the hot path.
type HMACKeyCache map[[16]byte][32]byte

// NewHMACKeyCache precomputes sha256(uuid) for every UUID.
// Call this once during server initialisation and reuse the result for the
// lifetime of the process — sha256.Sum256(uuid) is a constant per UUID.
func NewHMACKeyCache(uuids [][16]byte) HMACKeyCache {
	cache := make(HMACKeyCache, len(uuids))
	for _, uuid := range uuids {
		cache[uuid] = sha256.Sum256(uuid[:])
	}
	return cache
}

// computeHMACWithKey is the cached-key variant of computeHMAC.
// keyHash is sha256(uuid) precomputed by NewHMACKeyCache.
func computeHMACWithKey(keyHash [32]byte, ad, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(ad)
	h.Write(ciphertext)
	sum := h.Sum(nil)
	return sum[:16]
}

// DecodeHandshakeRequestCached is the hot-path variant of DecodeHandshakeRequest.
// It uses precomputed HMAC keys from a HMACKeyCache, eliminating the
// sha256.Sum256(uuid) call that would otherwise occur for every UUID candidate
// on every incoming connection.
func DecodeHandshakeRequestCached(data []byte, cache HMACKeyCache) (*HandshakeRequest, error) {
	if len(data) < 15+MinPayloadLength+16 {
		return nil, ErrInvalidLength
	}

	version := data[0]
	if version == 0 {
		return nil, ErrInvalidVersion
	}

	var nonce [12]byte
	copy(nonce[:], data[1:13])

	payloadLen := binary.BigEndian.Uint16(data[13:15])
	if payloadLen < MinPayloadLength || payloadLen > MaxPayloadLength {
		return nil, ErrInvalidLength
	}

	if len(data) < 15+int(payloadLen)+16 {
		return nil, ErrInvalidLength
	}

	ad := data[0:15]
	ciphertext := data[15 : 15+payloadLen]
	authTag := data[15+payloadLen : 15+payloadLen+16]

	for uuid, keyHash := range cache {
		// Use precomputed keyHash — no sha256.Sum256 per iteration.
		expectedTag := computeHMACWithKey(keyHash, ad, ciphertext)
		if !hmac.Equal(authTag, expectedTag) {
			continue
		}

		key := deriveEncryptionKey(uuid, nonce)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			continue
		}

		plaintext, err := aead.Open(nil, nonce[:], ciphertext, ad)
		if err != nil {
			continue
		}

		req := &HandshakeRequest{
			Version: version,
			Nonce:   nonce,
		}

		if len(plaintext) < 4+16+1+1+1+1 {
			continue
		}

		req.Timestamp = binary.BigEndian.Uint32(plaintext[0:4])
		copy(req.UUID[:], plaintext[4:20])
		req.Command = plaintext[20]

		now := time.Now().Unix()
		if math.Abs(float64(int64(req.Timestamp)-now)) > TimeWindow {
			return nil, ErrInvalidTimestamp
		}

		addr, addrLen, err := DecodeAddress(plaintext[21:])
		if err != nil {
			continue
		}
		req.TargetAddr = addr

		offset := 21 + addrLen
		if len(plaintext) < offset+2 {
			continue
		}

		req.Options = plaintext[offset]
		req.PaddingLength = plaintext[offset+1]

		return req, nil
	}

	return nil, ErrInvalidAuth
}

func ReadHandshake(r io.Reader) ([]byte, error) {
	// Read the 15-byte AD header onto the stack; parse payloadLen before any
	// heap allocation so we need exactly one make() for the complete packet.
	var hdr [15]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint16(hdr[13:15])
	if payloadLen < MinPayloadLength || payloadLen > MaxPayloadLength {
		return nil, ErrInvalidLength
	}

	// Single allocation: AD(15) + ciphertext(payloadLen) + outer HMAC(16).
	fullData := make([]byte, 15+int(payloadLen)+16)
	copy(fullData, hdr[:])
	if _, err := io.ReadFull(r, fullData[15:]); err != nil {
		return nil, err
	}
	return fullData, nil
}
