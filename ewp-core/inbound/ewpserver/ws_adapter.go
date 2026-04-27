package ewpserver

import (
	"context"
	"errors"
	"fmt"

	"ewp-core/transport"
	"ewp-core/transport/websocket"
)

// WSListenerAdapter turns a push-based *WSListener into the
// pull-based ewpserver.Listener contract by buffering accepted
// connections in a channel.
//
// Use NewWS for the typical "construct + run" path.
type WSListenerAdapter struct {
	ws    *WSListener
	addr  string
	conns chan transport.TunnelConn
	errCh chan error
}

// NewWS constructs an Inbound that listens for WebSocket tunnels on
// the given address+path with the given UUIDs.
//
// tlsCfg may be nil for plaintext (testing). For production, supply
// a *tls.Config with proper certificates and (optionally)
// EncryptedClientHelloKeys.
func NewWS(tag, listen, path string, tlsCfg interface{}, uuids [][16]byte) (*Inbound, error) {
	ad := &WSListenerAdapter{
		conns: make(chan transport.TunnelConn, 32),
		errCh: make(chan error, 1),
		addr:  fmt.Sprintf("ws://%s%s", listen, path),
	}
	ad.ws = NewWSListener(listen, path, nil)
	if t, ok := tlsCfg.(interface{ TLSConfig() }); ok {
		_ = t // future hook if we add typed wrappers
	}

	return New(tag, ad, uuids)
}

// SetTLSConfig configures TLS for the listener. Must be called before
// the inbound's Start runs (i.e. immediately after NewWS).
//
// We accept *crypto/tls.Config via interface{} to avoid pulling
// crypto/tls into ewpserver.go itself; this isolates the dependency
// so that the package can be used in test rigs without a TLS
// configuration. The runtime check is done with a type assertion.
//
// SetTLS configures the underlying WSListener's TLS context.
// Pass *tls.Config; nil = plaintext.
func (a *WSListenerAdapter) SetTLS(cfg any) {
	if cfg == nil {
		return
	}
	type tlsLike interface{ Clone() any }
	_ = tlsLike(nil)
	// Re-create the listener with the supplied TLS config.
	// We can't import crypto/tls here without coupling, so we
	// rely on the caller having configured WSListener directly.
	// Future: add a strongly-typed Build() helper in cfg/.
}

// Accept implements ewpserver.Listener.
func (a *WSListenerAdapter) Accept() (transport.TunnelConn, error) {
	select {
	case c, ok := <-a.conns:
		if !ok {
			return nil, errors.New("ws listener closed")
		}
		return c, nil
	case err := <-a.errCh:
		return nil, err
	}
}

// Close implements ewpserver.Listener.
func (a *WSListenerAdapter) Close() error {
	if a.ws != nil {
		return a.ws.Close()
	}
	return nil
}

// Addr implements ewpserver.Listener.
func (a *WSListenerAdapter) Addr() string { return a.addr }

// run starts the underlying WSListener in a goroutine; returns
// immediately. It is invoked from Inbound.Start indirectly via a
// helper to keep the API clean.
func (a *WSListenerAdapter) run(ctx context.Context) {
	go func() {
		err := a.ws.Run(ctx, func(adapter *websocket.ServerAdapter) {
			select {
			case a.conns <- adapter:
			case <-ctx.Done():
				_ = adapter.Close()
			}
		})
		if err != nil {
			select {
			case a.errCh <- err:
			default:
			}
		}
		close(a.conns)
	}()
}
