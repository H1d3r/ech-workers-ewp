package websocket

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"

	"github.com/lxzan/gws"
)

// Conn is the unified WebSocket tunnel connection for all three protocol variants
// (EWP-Simple, EWP-Flow, Trojan). It bridges gws's event-driven OnMessage API
// to the pull-based transport.TunnelConn.Read() interface via a buffered channel.
type Conn struct {
	gws.BuiltinEventHandler

	socket    *gws.Conn
	msgCh     chan *gws.Message
	closeCh   chan struct{}
	closeOnce sync.Once
	leftover  []byte

	uuid    [16]byte
	version byte
	nonce   [12]byte

	enableFlow        bool
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte

	useTrojan bool
	key       [trojan.KeyLength]byte

	udpGlobalID     [8]byte
	heartbeatPeriod time.Duration
	earlyDataLength int
	earlyDataSent   bool
}

func newConn(uuid [16]byte, password string, enableFlow, useTrojan bool) *Conn {
	c := &Conn{
		msgCh:      make(chan *gws.Message, 16),
		closeCh:    make(chan struct{}),
		uuid:       uuid,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
	}
	if useTrojan {
		c.key = trojan.GenerateKey(password)
	}
	return c
}

// --- gws.Event callbacks ---

func (c *Conn) OnClose(socket *gws.Conn, err error) {
	c.closeOnce.Do(func() { close(c.closeCh) })
}

func (c *Conn) OnPing(socket *gws.Conn, payload []byte) {
	_ = socket.WritePong(payload)
}

func (c *Conn) OnMessage(socket *gws.Conn, message *gws.Message) {
	select {
	case c.msgCh <- message:
	case <-c.closeCh:
		message.Close()
	}
}

// --- transport.TunnelConn ---

func (c *Conn) Read(buf []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(buf, c.leftover)
		c.leftover = c.leftover[n:]
		if len(c.leftover) == 0 {
			c.leftover = nil
		}
		return n, nil
	}
	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return 0, io.EOF
		}
		data := msg.Bytes()
		if c.enableFlow && c.flowState != nil {
			data = c.flowState.ProcessDownlink(data)
		}
		n := copy(buf, data)
		if n < len(data) {
			c.leftover = append(c.leftover[:0], data[n:]...)
		}
		msg.Close()
		return n, nil
	case <-c.closeCh:
		return 0, io.EOF
	}
}

func (c *Conn) Write(data []byte) error {
	if c.enableFlow && c.flowState != nil {
		data = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	}
	return c.socket.WriteMessage(gws.OpcodeBinary, data)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		_ = c.socket.WriteClose(1000, nil)
	})
	return nil
}

func (c *Conn) StartPing(interval time.Duration) chan struct{} {
	if c.heartbeatPeriod > 0 {
		interval = c.heartbeatPeriod
	}
	if interval == 0 {
		return make(chan struct{})
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = c.socket.WritePing(nil)
			case <-stop:
				return
			case <-c.closeCh:
				return
			}
		}
	}()
	return stop
}

func (c *Conn) SetEarlyData(length int)            { c.earlyDataLength = length }
func (c *Conn) SetHeartbeat(period time.Duration)  { c.heartbeatPeriod = period }

// --- Connect (TCP) ---

func (c *Conn) Connect(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojan(target, initialData)
	}
	return c.connectEWP(target, initialData)
}

func (c *Conn) connectEWP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if c.earlyDataLength > 0 && len(initialData) > 0 && len(initialData) <= c.earlyDataLength && !c.earlyDataSent {
		if err := c.socket.Writev(gws.OpcodeBinary, handshakeData, initialData); err != nil {
			return fmt.Errorf("send handshake+early data: %w", err)
		}
		c.earlyDataSent = true
	} else {
		if err := c.socket.WriteMessage(gws.OpcodeBinary, handshakeData); err != nil {
			return fmt.Errorf("send handshake: %w", err)
		}
	}

	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return fmt.Errorf("connection closed during handshake")
		}
		resp, err := ewp.DecodeHandshakeResponse(msg.Bytes(), c.version, c.nonce, c.uuid)
		msg.Close()
		if err != nil {
			return fmt.Errorf("decode handshake response: %w", err)
		}
		if resp.Status != ewp.StatusOK {
			return fmt.Errorf("handshake failed: status=%d", resp.Status)
		}
	case <-c.closeCh:
		return fmt.Errorf("connection closed during handshake")
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}
	if len(initialData) > 0 && !c.earlyDataSent {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}
	log.V("[EWP] WS TCP handshake ok: %s", target)
	return nil
}

func (c *Conn) connectTrojan(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}
	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	buf := make([]byte, 0, trojan.KeyLength+2+1+len(addrBytes)+2+len(initialData))
	buf = append(buf, c.key[:]...)
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, trojan.CommandTCP)
	buf = append(buf, addrBytes...)
	buf = append(buf, trojan.CRLF...)
	if len(initialData) > 0 {
		buf = append(buf, initialData...)
	}
	if err := c.socket.WriteMessage(gws.OpcodeBinary, buf); err != nil {
		return err
	}
	log.V("[Trojan] WS TCP handshake sent: %s", target)
	return nil
}

// --- ConnectUDP ---

func (c *Conn) ConnectUDP(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

func (c *Conn) connectEWPUDP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}
	if err := c.socket.WriteMessage(gws.OpcodeBinary, handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return fmt.Errorf("connection closed during UDP handshake")
		}
		resp, err := ewp.DecodeHandshakeResponse(msg.Bytes(), c.version, c.nonce, c.uuid)
		msg.Close()
		if err != nil {
			return fmt.Errorf("decode UDP handshake response: %w", err)
		}
		if resp.Status != ewp.StatusOK {
			return fmt.Errorf("UDP handshake failed: status=%d", resp.Status)
		}
	case <-c.closeCh:
		return fmt.Errorf("connection closed during UDP handshake")
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}
	c.udpGlobalID = ewp.NewGlobalID()
	pkt := &ewp.UDPPacket{
		GlobalID: c.udpGlobalID,
		Status:   ewp.UDPStatusNew,
		Target:   udpAddr,
		Payload:  initialData,
	}
	encoded, err := ewp.EncodeUDPPacket(pkt)
	if err != nil {
		return fmt.Errorf("encode UDP new packet: %w", err)
	}
	if err := c.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}
	log.V("[EWP] WS UDP handshake ok: %s", target)
	return nil
}

func (c *Conn) connectTrojanUDP(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}
	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	buf := make([]byte, 0, trojan.KeyLength+2+1+len(addrBytes)+2)
	buf = append(buf, c.key[:]...)
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, trojan.CommandUDP)
	buf = append(buf, addrBytes...)
	buf = append(buf, trojan.CRLF...)
	if err := c.socket.WriteMessage(gws.OpcodeBinary, buf); err != nil {
		return err
	}
	log.V("[Trojan] WS UDP handshake sent: %s", target)
	return nil
}

// --- WriteUDP ---

func (c *Conn) WriteUDP(target string, data []byte) error {
	if c.useTrojan {
		return c.writeTrojanUDP(target, data)
	}
	encoded, err := ewp.EncodeUDPKeepPacket(c.udpGlobalID, target, data)
	if err != nil {
		return fmt.Errorf("encode UDP keep packet: %w", err)
	}
	return c.Write(encoded)
}

func (c *Conn) writeTrojanUDP(target string, data []byte) error {
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
	return c.socket.WriteMessage(gws.OpcodeBinary, buf)
}

// --- ReadUDP ---

func (c *Conn) ReadUDP() ([]byte, error) {
	select {
	case msg, ok := <-c.msgCh:
		if !ok {
			return nil, io.EOF
		}
		data := msg.Bytes()
		var result []byte
		var err error
		if c.useTrojan {
			result, err = decodeTrojanUDP(data)
		} else {
			if c.enableFlow && c.flowState != nil {
				data = c.flowState.ProcessDownlink(data)
			}
			result, err = ewp.DecodeUDPPayload(data)
		}
		msg.Close()
		return result, err
	case <-c.closeCh:
		return nil, io.EOF
	}
}

func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	payload, err := c.ReadUDP()
	if err != nil {
		return 0, err
	}
	return copy(buf, payload), nil
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
	headerLen := offset + addrLen + 2
	if len(data) < headerLen+4 {
		return nil, fmt.Errorf("truncated trojan udp header")
	}
	payloadLen := int(data[headerLen])<<8 | int(data[headerLen+1])
	payloadStart := headerLen + 4
	if len(data) < payloadStart+payloadLen {
		return nil, fmt.Errorf("truncated trojan udp payload")
	}
	return data[payloadStart : payloadStart+payloadLen], nil
}
