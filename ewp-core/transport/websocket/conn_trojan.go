package websocket

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/trojan"

	"github.com/gorilla/websocket"
)

// TrojanConn implements Trojan protocol over WebSocket
type TrojanConn struct {
	conn            *websocket.Conn
	password        string
	key             [trojan.KeyLength]byte
	connected       bool
	mu              sync.Mutex
	heartbeatPeriod time.Duration
	udpGlobalID     [8]byte
}

// NewTrojanConn creates a new Trojan WebSocket connection
func NewTrojanConn(conn *websocket.Conn, password string) *TrojanConn {
	return &TrojanConn{
		conn:     conn,
		password: password,
		key:      trojan.GenerateKey(password),
	}
}

// Connect sends Trojan handshake
func (c *TrojanConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}

	// Build handshake data
	var handshakeData []byte
	handshakeData = append(handshakeData, c.key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandTCP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Append initial data if any
	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	// Send handshake (Trojan has no response)
	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return err
	}

	c.connected = true
	log.V("[Trojan] Handshake sent, target: %s", target)
	return nil
}

func (c *TrojanConn) ConnectUDP(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}

	// Build Trojan UDP handshake (without raw initial data)
	var handshakeData []byte
	handshakeData = append(handshakeData, c.key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Send Trojan handshake as first WebSocket message
	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return err
	}

	c.connected = true
	log.V("[Trojan] UDP handshake sent, target: %s", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel
func (c *TrojanConn) WriteUDP(target string, data []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	length := uint16(len(data))
	buf := make([]byte, 0, len(addrBytes)+4+len(data))
	buf = append(buf, addrBytes...)
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, data...)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, buf)
}

// ReadUDP reads and decodes a Trojan-framed UDP response packet
func (c *TrojanConn) ReadUDP() ([]byte, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return decodeTrojanUDP(msg)
}

// ReadUDPTo reads and decodes a Trojan-framed UDP response packet directly into the provided buffer
func (c *TrojanConn) ReadUDPTo(buf []byte) (int, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	payload, err := decodeTrojanUDP(msg)
	if err != nil {
		return 0, err
	}
	n := copy(buf, payload)
	return n, nil
}

func decodeTrojanUDP(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty trojan udp payload")
	}
	offset := 1
	var addrLen int
	switch data[0] {
	case trojan.AddressTypeIPv4:
		addrLen = 4
	case trojan.AddressTypeIPv6:
		addrLen = 16
	case trojan.AddressTypeDomain:
		if len(data) < 2 {
			return nil, fmt.Errorf("truncated trojan domain")
		}
		addrLen = int(data[1])
		offset++
	default:
		return nil, fmt.Errorf("unknown trojan address type: %d", data[0])
	}
	
	headerLen := offset + addrLen + 2 // Type + Addr + Port
	if len(data) < headerLen+4 { // + Length(2) + CRLF(2)
		return nil, fmt.Errorf("truncated trojan udp header")
	}
	
	payloadLen := int(data[headerLen])<<8 | int(data[headerLen+1])
	payloadStart := headerLen + 4
	
	if len(data) < payloadStart+payloadLen {
		return nil, fmt.Errorf("truncated trojan udp payload")
	}
	return data[payloadStart : payloadStart+payloadLen], nil
}

// Read reads data from WebSocket
func (c *TrojanConn) Read(buf []byte) (int, error) {
	msgType, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// Check for control messages
	if msgType == websocket.TextMessage {
		str := string(msg)
		if str == "CLOSE" {
			return 0, io.EOF
		}
		if strings.HasPrefix(str, "ERROR:") {
			return 0, errors.New(str)
		}
	}

	n := copy(buf, msg)
	return n, nil
}

// Write writes data to WebSocket
func (c *TrojanConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Close closes the connection
func (c *TrojanConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
	return c.conn.Close()
}

// StartPing starts heartbeat
func (c *TrojanConn) StartPing(interval time.Duration) chan struct{} {
	if c.heartbeatPeriod > 0 {
		interval = c.heartbeatPeriod
	}
	if interval == 0 {
		return make(chan struct{})
	}

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				err := c.conn.WriteMessage(websocket.PingMessage, nil)
				c.mu.Unlock()
				if err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()
	return stop
}
