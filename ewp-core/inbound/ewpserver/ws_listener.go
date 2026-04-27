package ewpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/lxzan/gws"

	"ewp-core/log"
	"ewp-core/transport/websocket"
)

// WSListener accepts WebSocket connections (over TLS) and hands each
// upgraded conn to the supplied callback as a transport.TunnelConn.
//
// It does NOT terminate ECH itself; if you want server-side ECH
// termination, supply a *tls.Config with EncryptedClientHelloKeys
// already populated. (Go 1.24+.)
type WSListener struct {
	listen string
	path   string
	tlsCfg *tls.Config // nil = plaintext WS (testing only)

	mu     sync.Mutex
	server *http.Server
	closed bool
}

// NewWSListener creates a TLS WebSocket listener for the given path.
// Pass tlsCfg=nil only for in-process tests.
func NewWSListener(listen, path string, tlsCfg *tls.Config) *WSListener {
	if path == "" {
		path = "/"
	}
	return &WSListener{listen: listen, path: path, tlsCfg: tlsCfg}
}

// Run blocks accepting new connections until ctx is cancelled or the
// underlying http.Server returns. Each accepted connection is handed
// to onConn in its own goroutine; onConn must take ownership of
// closing.
func (l *WSListener) Run(ctx context.Context, onConn func(*websocket.ServerAdapter)) error {
	mux := http.NewServeMux()
	mux.HandleFunc(l.path, func(w http.ResponseWriter, r *http.Request) {
		adapter := websocket.NewServerAdapter()
		up := gws.NewUpgrader(adapter, &gws.ServerOption{})
		socket, err := up.Upgrade(w, r)
		if err != nil {
			log.V("[ewpserver/ws] upgrade: %v", err)
			return
		}
		adapter.SetSocket(socket)
		go socket.ReadLoop()
		onConn(adapter)
	})

	srv := &http.Server{
		Addr:      l.listen,
		Handler:   mux,
		TLSConfig: l.tlsCfg,
	}
	l.mu.Lock()
	l.server = srv
	l.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	if l.tlsCfg != nil {
		err := srv.ListenAndServeTLS("", "")
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("ws listener: %w", err)
	}

	// Plaintext fallback (tests).
	ln, err := net.Listen("tcp", l.listen)
	if err != nil {
		return fmt.Errorf("ws listen: %w", err)
	}
	if e := srv.Serve(ln); !errors.Is(e, http.ErrServerClosed) {
		return fmt.Errorf("ws serve: %w", e)
	}
	return nil
}

// Close stops accepting new connections.
func (l *WSListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}
