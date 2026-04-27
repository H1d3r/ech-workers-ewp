package ewpserver

import (
	"context"
	"crypto/tls"

	"ewp-core/transport"
)

// NewWSListenerWithTLS is the public-facing constructor used by
// cmd/ewp/cfg.  It returns a ready-to-Accept Listener that lazily
// starts its underlying HTTP server on first Accept().
//
// Pass tlsCfg=nil for plaintext (testing only).
func NewWSListenerWithTLS(listen, path string, tlsCfg *tls.Config) Listener {
	ad := &WSListenerAdapter{
		conns: make(chan transport.TunnelConn, 32),
		errCh: make(chan error, 1),
		addr:  listen + path,
	}
	ad.ws = NewWSListener(listen, path, tlsCfg)
	// Eagerly start the accept loop on a background context. Engine
	// shutdown drives Close() on us via Inbound.Close(), which then
	// closes WSListener and unblocks the goroutine.
	ad.run(context.Background())
	return ad
}
