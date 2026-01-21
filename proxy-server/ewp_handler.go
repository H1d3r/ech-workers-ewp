package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"

	"proxy-server/ewp"
)

var validUUIDs [][16]byte

func initEWPHandler(uuidStr string) error {
	validUUIDs = make([][16]byte, 0)
	
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
		
		validUUIDs = append(validUUIDs, uuid)
		log.Printf("[EWP] Registered UUID: %s", u)
	}
	
	if len(validUUIDs) == 0 {
		return fmt.Errorf("no valid UUIDs configured")
	}
	
	return nil
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	
	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(s))
	}
	
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}
	
	copy(uuid[:], decoded)
	return uuid, nil
}

func handleEWPHandshake(reader io.Reader) (*ewp.HandshakeRequest, []byte, error) {
	handshakeData, err := ewp.ReadHandshake(reader)
	if err != nil {
		log.Printf("❌ EWP: Failed to read handshake: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	req, err := ewp.DecodeHandshakeRequest(handshakeData, validUUIDs)
	if err != nil {
		log.Printf("❌ EWP: Handshake validation failed: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Printf("❌ EWP: Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Printf("✅ EWP: Handshake successful, target: %s", req.TargetAddr.String())
	return req, respData, nil
}

func handleEWPHandshakeBinary(data []byte) (*ewp.HandshakeRequest, []byte, error) {
	req, err := ewp.DecodeHandshakeRequest(data, validUUIDs)
	if err != nil {
		log.Printf("❌ EWP: Handshake validation failed: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	resp := ewp.NewSuccessResponse(req.Version, req.Nonce)
	respData, err := resp.Encode(req.UUID)
	if err != nil {
		log.Printf("❌ EWP: Failed to encode response: %v", err)
		return nil, ewp.GenerateFakeResponse(), err
	}

	log.Printf("✅ EWP: Handshake successful, target: %s", req.TargetAddr.String())
	return req, respData, nil
}
