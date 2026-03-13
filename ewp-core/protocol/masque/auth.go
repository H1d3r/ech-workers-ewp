package masque

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
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
	if math.Abs(float64(int64(ts)-now)) > TimeWindow {
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

func computeAuthHMAC(uuid [16]byte, tsNonce []byte) []byte {
	keyHash := sha256.Sum256(uuid[:])
	h := hmac.New(sha256.New, keyHash[:])
	h.Write(uuid[:])
	h.Write(tsNonce)
	h.Write([]byte("masque-v1"))
	return h.Sum(nil)
}
