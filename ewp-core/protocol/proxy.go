package protocol

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ewp-core/log"
	"ewp-core/transport"
)

var (
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}

	activeConns   int64
	totalUpload   int64
	totalDownload int64
)

type TunnelHandler struct {
	transport atomic.Value // stores transport.Transport for hot reload (P2-25)
}

func NewTunnelHandler(trans transport.Transport) *TunnelHandler {
	h := &TunnelHandler{}
	h.transport.Store(trans)
	return h
}

// P2-25: UpdateTransport atomically updates the transport for hot reload
func (h *TunnelHandler) UpdateTransport(trans transport.Transport) {
	h.transport.Store(trans)
}

// getTransport returns the current transport
func (h *TunnelHandler) getTransport() transport.Transport {
	return h.transport.Load().(transport.Transport)
}

func (h *TunnelHandler) HandleTunnel(conn net.Conn, target string, clientAddr string, initialData []byte, sendSuccessReply func() error) error {
	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	// P2-25: Get current transport (may be updated by hot reload)
	trans := h.getTransport()
	tunnelConn, err := trans.Dial()
	if err != nil {
		return err
	}
	defer tunnelConn.Close()

	stopPing := tunnelConn.StartPing(30 * time.Second)
	defer close(stopPing)

	conn.SetDeadline(time.Time{})

	if err := tunnelConn.Connect(target, initialData); err != nil {
		return err
	}

	if err := sendSuccessReply(); err != nil {
		return err
	}

	log.V("[Proxy] %s connected: %s", clientAddr, target)

	done := make(chan bool, 2)

	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
			atomic.AddInt64(&totalUpload, int64(n))
		}
	}()

	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := tunnelConn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if _, err := conn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
			atomic.AddInt64(&totalDownload, int64(n))
		}
	}()

	<-done
	log.V("[Proxy] %s disconnected: %s", clientAddr, target)
	return nil
}

// Dial creates a new tunnel connection for UDP sessions.
func (h *TunnelHandler) Dial() (transport.TunnelConn, error) {
	// P2-25: Get current transport (may be updated by hot reload)
	trans := h.getTransport()
	return trans.Dial()
}

// IsNormalCloseError checks if an error represents a normal connection closure
// P2-8: Use errors.Is instead of string matching for better maintainability
func IsNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	
	// P2-8: Use errors.Is for standard errors
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	
	// Check for common network close errors using errors.Is
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		// Connection reset, broken pipe, etc.
		if netErr.Err != nil {
			errStr := netErr.Err.Error()
			if strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "broken pipe") {
				return true
			}
		}
	}
	
	// WebSocket normal closure
	errStr := err.Error()
	if strings.Contains(errStr, "normal closure") {
		return true
	}
	
	return false
}

func GetStats() (active, upload, download int64) {
	return atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalUpload), atomic.LoadInt64(&totalDownload)
}
