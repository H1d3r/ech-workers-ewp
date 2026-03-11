package webtransport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"
	ewpserver "ewp-core/internal/server"

	wtransport "github.com/quic-go/webtransport-go"
)

// Handler is an HTTP handler that upgrades WebTransport sessions and routes
// each accepted bidi stream as an EWP tunnel connection.
//
// Usage:
//
//	wtServer := &webtransport.Server{H3: &http3.Server{...}}
//	mux.Handle("/wt", webtransport.NewHandler(wtServer, enableFlow))
type Handler struct {
	wtServer  *wtransport.Server
	enableFlow bool
}

// NewHandler creates a Handler wrapping an existing webtransport.Server.
// The handler must be registered at the path used by clients.
func NewHandler(wtServer *wtransport.Server, enableFlow bool) *Handler {
	return &Handler{wtServer: wtServer, enableFlow: enableFlow}
}

// ServeHTTP upgrades the HTTP/3 request to a WebTransport session,
// then accepts streams in a loop, each handled in its own goroutine.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, err := h.wtServer.Upgrade(w, r)
	if err != nil {
		log.Warn("[WebTransport] Upgrade failed from %s: %v", r.RemoteAddr, err)
		return
	}

	clientIP := r.RemoteAddr
	log.V("[WebTransport] Session opened from %s", clientIP)

	for {
		stream, err := sess.AcceptStream(r.Context())
		if err != nil {
			log.V("[WebTransport] Session closed for %s: %v", clientIP, err)
			return
		}
		go h.handleStream(stream, clientIP)
	}
}

// handleStream processes one bidi stream: EWP handshake → TCP relay or UDP relay.
func (h *Handler) handleStream(stream *wtransport.Stream, clientIP string) {
	defer stream.Close()

	handshakeData, err := ewp.ReadHandshake(stream)
	if err != nil {
		log.Warn("[WebTransport] Failed to read handshake from %s: %v", clientIP, err)
		return
	}

	req, respData, err := ewpserver.HandleEWPHandshakeBinary(handshakeData, clientIP)
	if err != nil {
		log.Warn("[WebTransport] Handshake rejected from %s: %v", clientIP, err)
		if len(respData) > 0 {
			stream.Write(respData)
		}
		return
	}

	if _, err := stream.Write(respData); err != nil {
		log.Warn("[WebTransport] Failed to send response to %s: %v", clientIP, err)
		return
	}

	target := req.TargetAddr.String()
	userID := fmt.Sprintf("%x", req.UUID[:8])

	if req.Command == ewp.CommandUDP {
		log.Info("[WebTransport] UDP mode: %s (user: %s) -> %s", clientIP, userID, target)
		ewpserver.HandleUDPConnection(stream, stream, target)
		log.Info("[WebTransport] UDP closed: %s -> %s", clientIP, target)
		return
	}

	// TCP relay
	log.Info("[WebTransport] TCP: %s (user: %s) -> %s", clientIP, userID, target)

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	remote, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		log.Warn("[WebTransport] Dial failed to %s: %v", target, err)
		return
	}
	defer remote.Close()

	log.Info("[WebTransport] Connected: %s -> %s", clientIP, target)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remote, stream)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, remote)
		stream.CancelRead(0)
	}()

	wg.Wait()
	log.Info("[WebTransport] Closed: %s -> %s", clientIP, target)
}
