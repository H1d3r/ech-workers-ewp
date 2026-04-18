package server

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	log "ewp-core/log"
	"ewp-core/protocol/ewp"
)

var (
	ValidUUIDs  [][16]byte
	uuidCache   ewp.UUIDKeyCache
	NonceCache  *ewp.NonceCache
	RateLimiter *ewp.RateLimiter
)

func InitEWPHandler(uuidStr string) error {
	ValidUUIDs = make([][16]byte, 0)

	uuids := strings.Split(uuidStr, ",")
	for _, u := range uuids {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}

		uuid, err := parseUUID(u)
		if err != nil {
			return fmt.Errorf("invalid UUID %s: %w", u, err)
		}

		ValidUUIDs = append(ValidUUIDs, uuid)
		log.Info("[EWP] Registered UUID: %s", u)
	}

	if len(ValidUUIDs) == 0 {
		return fmt.Errorf("no valid UUIDs configured")
	}

	uuidCache = ewp.NewUUIDKeyCache(ValidUUIDs)
	NonceCache = ewp.NewNonceCache()
	RateLimiter = ewp.NewRateLimiter(300, 5*time.Second)

	log.Info("[EWP] Nonce cache and rate limiter initialized (maxRate=300/s, banTime=5s)")

	return nil
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	
	// Bug-A: Validate RFC 4122 format before removing hyphens
	// Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars with hyphens)
	if len(s) != 36 {
		return uuid, fmt.Errorf("invalid UUID format: expected 36 characters, got %d", len(s))
	}
	
	// Bug-A: Validate hyphen positions (8-4-4-4-12)
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return uuid, fmt.Errorf("invalid UUID format: hyphens must be at positions 8, 13, 18, 23")
	}
	
	// Remove hyphens for hex decoding
	s = strings.ReplaceAll(s, "-", "")

	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length after removing hyphens: %d", len(s))
	}

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}

	copy(uuid[:], decoded)
	
	// P2-23: Reject nil UUID (all zeros) - weak credential
	isNil := true
	for _, b := range uuid {
		if b != 0 {
			isNil = false
			break
		}
	}
	if isNil {
		return uuid, fmt.Errorf("nil UUID (all zeros) is not allowed - weak credential")
	}
	
	return uuid, nil
}

func HandleEWPHandshakeBinary(data []byte, clientIP string) (*ewp.HandshakeRequest, []byte, error) {
	if !RateLimiter.Allow(clientIP) {
		log.Warn("[EWP] Rate limit exceeded for %s", clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("rate limit exceeded")
	}

	req, err := ewp.DecodeHandshakeRequestCached(data, uuidCache)
	if err != nil {
		log.Warn("[EWP] Handshake failed from %s: %v", clientIP, err)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), err
	}

	if NonceCache.CheckAndAdd(req.Nonce) {
		log.Warn("[EWP] Replay attack (duplicate nonce) from %s", clientIP)
		RateLimiter.RecordFailure(clientIP)
		return nil, ewp.GenerateFakeResponse(), fmt.Errorf("replay attack detected")
	}

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Error("[EWP] Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Info("[EWP] Handshake from %s -> %s", clientIP, req.TargetAddr.String())
	return req, respData, nil
}
