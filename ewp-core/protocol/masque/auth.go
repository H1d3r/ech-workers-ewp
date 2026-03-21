package masque

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"
)

const (
	HeaderAuth  = "X-Masque-Auth"
	TimeWindow  = 120

	tokenLen = 16 + 4 + 8 + 16
)

// GenerateAuthHeader builds the X-Masque-Auth header for a QUIC/HTTP3 request.
//
// Token layout (44 bytes, base64-encoded):
//
//	UUID[16] | Timestamp[4] | Nonce[8] | HMAC-SHA256[:16]
//
// The HMAC key is SHA-256(uuid) and the message is UUID||Timestamp||Nonce||"masque-v1".
func GenerateAuthHeader(uuid [16]byte) (http.Header, error) {
	var token [tokenLen]byte

	copy(token[:16], uuid[:])

	binary.BigEndian.PutUint32(token[16:20], uint32(time.Now().Unix()))

	if _, err := rand.Read(token[20:28]); err != nil {
		return nil, fmt.Errorf("masque auth: generate nonce: %w", err)
	}

	tag := computeAuthHMAC(uuid, token[16:28])
	copy(token[28:], tag[:16])

	h := make(http.Header)
	h.Set(HeaderAuth, base64.RawStdEncoding.EncodeToString(token[:]))
	return h, nil
}

// ValidateAuthHeader validates the X-Masque-Auth header.
// Returns the matched UUID on success.
func ValidateAuthHeader(h http.Header, validUUIDs [][16]byte) ([16]byte, error) {
	raw := h.Get(HeaderAuth)
	if raw == "" {
		return [16]byte{}, fmt.Errorf("masque auth: missing header")
	}

	decoded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(decoded) != tokenLen {
		return [16]byte{}, fmt.Errorf("masque auth: malformed token")
	}

	var uuid [16]byte
	copy(uuid[:], decoded[:16])

	ts := binary.BigEndian.Uint32(decoded[16:20])
	now := time.Now().Unix()
	diff := int64(ts) - now
	if diff < -TimeWindow || diff > TimeWindow {
		return [16]byte{}, fmt.Errorf("masque auth: timestamp out of window")
	}

	receivedTag := decoded[28:44]

	for _, candidate := range validUUIDs {
		if candidate != uuid {
			continue
		}
		expected := computeAuthHMAC(candidate, decoded[16:28])
		if hmac.Equal(receivedTag, expected[:16]) {
			return uuid, nil
		}
	}

	return [16]byte{}, fmt.Errorf("masque auth: authentication failed")
}

// HMACKeyCache maps UUID → precomputed sha256(uuid), eliminating per-request
// SHA-256 key derivation on the MASQUE auth hot path.
// Build once at startup via NewHMACKeyCache; pass to ValidateAuthHeaderCached.
type HMACKeyCache map[[16]byte][32]byte

// NewHMACKeyCache precomputes sha256(uuid) for every UUID.
// Call once during server initialisation; the result is read-only and safe
// to share across goroutines without any locking.
func NewHMACKeyCache(uuids [][16]byte) HMACKeyCache {
	cache := make(HMACKeyCache, len(uuids))
	for _, uuid := range uuids {
		cache[uuid] = sha256.Sum256(uuid[:])
	}
	return cache
}

// ValidateAuthHeaderCached validates X-Masque-Auth using precomputed HMAC keys.
//
// Compared to ValidateAuthHeader, this variant eliminates the sha256.Sum256(uuid)
// call that would otherwise occur for every candidate UUID on every incoming
// request. The HMAC computation itself (hmac.New + Write + Sum) is unchanged —
// it is inherently per-request because the message includes a fresh nonce.
func ValidateAuthHeaderCached(h http.Header, cache HMACKeyCache) ([16]byte, error) {
	raw := h.Get(HeaderAuth)
	if raw == "" {
		return [16]byte{}, fmt.Errorf("masque auth: missing header")
	}

	decoded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(decoded) != tokenLen {
		return [16]byte{}, fmt.Errorf("masque auth: malformed token")
	}

	var uuid [16]byte
	copy(uuid[:], decoded[:16])

	ts := binary.BigEndian.Uint32(decoded[16:20])
	now := time.Now().Unix()
	diff := int64(ts) - now
	if diff < -TimeWindow || diff > TimeWindow {
		return [16]byte{}, fmt.Errorf("masque auth: timestamp out of window")
	}

	receivedTag := decoded[28:44]

	keyHash, ok := cache[uuid]
	if !ok {
		return [16]byte{}, fmt.Errorf("masque auth: authentication failed")
	}
	// Use precomputed keyHash instead of sha256.Sum256(uuid[:]).
	expected := computeAuthHMACWithKey(keyHash, uuid, decoded[16:28])
	if hmac.Equal(receivedTag, expected[:16]) {
		return uuid, nil
	}
	return [16]byte{}, fmt.Errorf("masque auth: authentication failed")
}

func computeAuthHMAC(uuid [16]byte, tsNonce []byte) []byte {
	keyHash := sha256.Sum256(uuid[:])
	return computeAuthHMACWithKey(keyHash, uuid, tsNonce)
}

// computeAuthHMACWithKey is the cached-key variant: keyHash = sha256(uuid)
// precomputed by NewHMACKeyCache, avoiding per-request SHA-256 key derivation.
func computeAuthHMACWithKey(keyHash [32]byte, uuid [16]byte, tsNonce []byte) []byte {
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(uuid[:])
	h.Write(tsNonce)
	h.Write([]byte("masque-v1"))
	return h.Sum(nil)
}
