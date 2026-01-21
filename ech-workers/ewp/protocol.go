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
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version1 = 0x01

	CommandTCP byte = 0x01
	CommandUDP byte = 0x02

	OptionMux           byte = 0x01
	OptionDataEncryption byte = 0x02

	MinPaddingLength = 64
	MaxPaddingLength = 255
	TimeWindow       = 120

	MinPayloadLength = 64
	MaxPayloadLength = 512
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
	req := &HandshakeRequest{
		Version:       byte(mrand.Intn(255) + 1),
		Timestamp:     uint32(time.Now().Unix()),
		UUID:          uuid,
		Command:       command,
		TargetAddr:    addr,
		Options:       0,
		PaddingLength: byte(mrand.Intn(MaxPaddingLength-MinPaddingLength+1) + MinPaddingLength),
	}
	rand.Read(req.Nonce[:])
	return req
}

func (r *HandshakeRequest) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)

	payload := new(bytes.Buffer)
	binary.Write(payload, binary.BigEndian, r.Timestamp)
	payload.Write(r.UUID[:])
	payload.WriteByte(r.Command)

	addrBytes, err := r.TargetAddr.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode address: %w", err)
	}
	payload.Write(addrBytes)

	payload.WriteByte(r.Options)
	payload.WriteByte(r.PaddingLength)

	padding := make([]byte, r.PaddingLength)
	rand.Read(padding)
	payload.Write(padding)

	plaintextPayload := payload.Bytes()

	key := deriveEncryptionKey(r.UUID, r.Nonce)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	ad := make([]byte, 15)
	ad[0] = r.Version
	copy(ad[1:13], r.Nonce[:])
	binary.BigEndian.PutUint16(ad[13:15], uint16(len(plaintextPayload)))

	ciphertext := aead.Seal(nil, r.Nonce[:], plaintextPayload, ad)

	authTag := computeHMAC(r.UUID, ad, ciphertext)

	buf.Write(ad)
	buf.Write(ciphertext)
	buf.Write(authTag)

	return buf.Bytes(), nil
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
	buf := new(bytes.Buffer)

	buf.WriteByte(r.VersionEcho)
	buf.WriteByte(r.Status)
	binary.Write(buf, binary.BigEndian, r.ServerTime)
	buf.Write(r.NonceEcho[:])

	msg := buf.Bytes()[:17]
	tag := computeResponseHMAC(uuid, msg)
	copy(r.AuthTag[:], tag[:8])

	buf.Write(r.AuthTag[:])

	return buf.Bytes(), nil
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

func ReadHandshake(r io.Reader) ([]byte, error) {
	header := make([]byte, 15)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint16(header[13:15])
	if payloadLen < MinPayloadLength || payloadLen > MaxPayloadLength {
		return nil, ErrInvalidLength
	}

	rest := make([]byte, int(payloadLen)+16)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}

	fullData := append(header, rest...)
	return fullData, nil
}
