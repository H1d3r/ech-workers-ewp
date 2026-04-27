package ewpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go/http3"

	"ewp-core/log"
	"ewp-core/transport"
	h3transport "ewp-core/transport/h3grpc"
)

// NewH3Listener returns a Listener that accepts EWP-over-HTTP/3+gRPC-Web
// tunnels.
//
// listen is a bind address (e.g. ":443"); path is the URL path the
// client posts to (e.g. "/ewp"). tlsCfg is required because QUIC has
// no plaintext mode; supply server cert/key (and optionally
// EncryptedClientHelloKeys) the same way as for the WS listener.
func NewH3Listener(listen, path string, tlsCfg *tls.Config) Listener {
	if path == "" {
		path = "/"
	}
	if tlsCfg == nil {
		// Fail loud rather than start a "listening on QUIC-without-TLS"
		// listener that will reject every client.
		log.Printf("[ewpserver/h3] WARNING: TLS config is nil; HTTP/3 cannot run without TLS")
	}
	tlsCfg = ensureH3ALPN(tlsCfg)
	return &h3ListenerAdapter{
		listen: listen,
		path:   path,
		tlsCfg: tlsCfg,
		conns:  make(chan transport.TunnelConn, 32),
	}
}

func ensureH3ALPN(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	out := cfg.Clone()
	hasH3 := false
	for _, p := range out.NextProtos {
		if p == "h3" {
			hasH3 = true
			break
		}
	}
	if !hasH3 {
		out.NextProtos = append([]string{"h3"}, out.NextProtos...)
	}
	return out
}

type h3ListenerAdapter struct {
	listen string
	path   string
	tlsCfg *tls.Config
	conns  chan transport.TunnelConn

	mu     sync.Mutex
	srv    *http3.Server
	closed bool
}

func (h *h3ListenerAdapter) run(ctx context.Context) {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc(h.path, h.handleStream)

		srv := &http3.Server{
			Addr:      h.listen,
			Handler:   mux,
			TLSConfig: h.tlsCfg,
		}
		h.mu.Lock()
		h.srv = srv
		h.mu.Unlock()

		go func() {
			<-ctx.Done()
			h.Close()
		}()

		log.Printf("[ewpserver/h3] listening on %s%s", h.listen, h.path)
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.V("[ewpserver/h3] serve: %v", err)
		}
		close(h.conns)
	}()
}

func (h *h3ListenerAdapter) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming required", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/grpc-web+proto")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	dec := h3transport.NewGRPCWebDecoder(r.Body)
	enc := h3transport.NewGRPCWebEncoder(&flushingWriter{w: w, f: flusher}, false)

	conn := newH3TunnelConn(dec, enc)
	select {
	case h.conns <- conn:
	case <-r.Context().Done():
		return
	}
	// Block until the connection is closed; returning here would
	// terminate the HTTP/3 stream.
	<-conn.done
}

func (h *h3ListenerAdapter) Accept() (transport.TunnelConn, error) {
	c, ok := <-h.conns
	if !ok {
		return nil, errors.New("h3 listener closed")
	}
	return c, nil
}

func (h *h3ListenerAdapter) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if h.srv != nil {
		_ = h.srv.Close()
	}
	return nil
}

func (h *h3ListenerAdapter) Addr() string {
	return "h3://" + h.listen + h.path
}

// h3TunnelConn wraps a grpc-web encoder/decoder pair as a TunnelConn.
type h3TunnelConn struct {
	dec  *h3transport.GRPCWebDecoder
	enc  *h3transport.GRPCWebEncoder
	done chan struct{}
	once sync.Once
}

func newH3TunnelConn(dec *h3transport.GRPCWebDecoder, enc *h3transport.GRPCWebEncoder) *h3TunnelConn {
	return &h3TunnelConn{dec: dec, enc: enc, done: make(chan struct{})}
}

func (c *h3TunnelConn) SendMessage(b []byte) error    { return c.enc.Encode(b) }
func (c *h3TunnelConn) ReadMessage() ([]byte, error)  { return c.dec.Decode() }
func (c *h3TunnelConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

// flushingWriter forwards writes to the underlying ResponseWriter
// and flushes after each chunk so the gRPC-Web frame reaches the
// client immediately.
type flushingWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (w *flushingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil {
		w.f.Flush()
	}
	return n, err
}
