package protocol

import (
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
	transport transport.Transport
}

func NewTunnelHandler(trans transport.Transport) *TunnelHandler {
	return &TunnelHandler{
		transport: trans,
	}
}

func (h *TunnelHandler) HandleTunnel(conn net.Conn, target string, clientAddr string, initialData []byte, sendSuccessReply func() error) error {
	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		return err
	}
	defer tunnelConn.Close()

	stopPing := tunnelConn.StartPing(30 * time.Second)
	if stopPing != nil {
		defer close(stopPing)
	}

	conn.SetDeadline(time.Time{})

	if err := tunnelConn.Connect(target, initialData); err != nil {
		return err
	}

	if err := sendSuccessReply(); err != nil {
		return err
	}

	log.V("[Proxy] %s connected: %s", clientAddr, target)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				tunnelConn.Close()
				return
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				conn.Close()
				return
			}
			atomic.AddInt64(&totalUpload, int64(n))
		}
	}()

	go func() {
		defer wg.Done()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := tunnelConn.Read(buf)
			if err != nil {
				conn.Close()
				return
			}

			if _, err := conn.Write(buf[:n]); err != nil {
				tunnelConn.Close()
				return
			}
			atomic.AddInt64(&totalDownload, int64(n))
		}
	}()

	wg.Wait()
	log.V("[Proxy] %s disconnected: %s", clientAddr, target)
	return nil
}

// Dial creates a new tunnel connection for UDP sessions.
func (h *TunnelHandler) Dial() (transport.TunnelConn, error) {
	return h.transport.Dial()
}

func IsNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

func GetStats() (active, upload, download int64) {
	return atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalUpload), atomic.LoadInt64(&totalDownload)
}
