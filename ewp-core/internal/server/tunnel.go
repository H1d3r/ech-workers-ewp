package server

import (
	"context"
	"net"
	"time"

	"ewp-core/log"
)

type TunnelOptions struct {
	Protocol  ProtocolHandler
	Transport TransportAdapter
	ClientIP  string
	Timeout   time.Duration
}

func EstablishTunnel(ctx context.Context, handshakeData []byte, opts TunnelOptions) error {
	result, err := opts.Protocol.Handshake(handshakeData, opts.ClientIP)
	if err != nil {
		log.Warn("[Tunnel] Handshake failed from %s: %v", opts.ClientIP, err)
		if result != nil && len(result.Response) > 0 {
			opts.Transport.Write(result.Response)
		}
		return err
	}

	log.Info("[Tunnel] Handshake OK from %s (user: %s) -> %s", opts.ClientIP, result.UserID, result.Target)

	if len(result.Response) > 0 {
		if err := opts.Transport.Write(result.Response); err != nil {
			log.Warn("[Tunnel] Failed to send handshake response: %v", err)
			return err
		}
	}

	if result.IsUDP {
		log.Info("[Tunnel] UDP mode: %s -> %s", opts.ClientIP, result.Target)

		// Create io.Reader/io.Writer adapter for TransportAdapter
		rw := &transportReaderWriter{transport: opts.Transport}

		// Route to protocol-specific UDP handler
		if result.IsTrojan {
			HandleTrojanUDPConnection(rw, rw)
		} else {
			HandleUDPConnection(rw, rw)
		}

		log.Info("[Tunnel] UDP closed: %s -> %s", opts.ClientIP, result.Target)
		return nil
	}

	dialCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var d net.Dialer
	remote, err := d.DialContext(dialCtx, "tcp", result.Target)
	if err != nil {
		log.Warn("[Tunnel] Dial failed to %s: %v", result.Target, err)
		return err
	}
	defer remote.Close()

	log.Info("[Tunnel] Connected: %s -> %s", opts.ClientIP, result.Target)

	if len(result.InitialData) > 0 {
		if _, err := remote.Write(result.InitialData); err != nil {
			log.Warn("[Tunnel] Failed to write initial data: %v", err)
			return err
		}
	}

	forwarder := NewTunnelForwarder(opts.Transport, remote, result.FlowState)
	forwarder.Forward()

	log.Info("[Tunnel] Closed: %s -> %s", opts.ClientIP, result.Target)
	return nil
}

// transportReaderWriter adapts TransportAdapter to io.Reader/io.Writer.
//
// Each transport.Read() call returns one complete framed message. Callers like
// DecodeUDPPacket use io.ReadFull with small successive buffers (e.g. 2-byte
// length prefix then N-byte body). Without leftover tracking, every small
// Read() call would fetch a brand-new transport frame and silently discard the
// previous frame's unread tail — catastrophic data loss.
//
// leftover holds bytes from the last transport frame that didn't fit into the
// caller's buffer. It is always a freshly-allocated copy (never a sub-slice of
// the transport's internal buffer) to prevent data corruption when the
// transport reuses its read buffer for the next frame.
type transportReaderWriter struct {
	transport TransportAdapter
	leftover  []byte
}

func (t *transportReaderWriter) Read(p []byte) (n int, err error) {
	if len(t.leftover) > 0 {
		n = copy(p, t.leftover)
		t.leftover = t.leftover[n:]
		if len(t.leftover) == 0 {
			t.leftover = nil
		}
		return n, nil
	}

	data, err := t.transport.Read()
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}

	n = copy(p, data)
	if n < len(data) {
		t.leftover = append([]byte(nil), data[n:]...)
	}
	return n, nil
}

func (t *transportReaderWriter) Write(p []byte) (n int, err error) {
	err = t.transport.Write(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
