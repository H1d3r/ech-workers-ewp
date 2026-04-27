package ewpserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"ewp-core/log"
	"ewp-core/transport"
)

// NewXHTTPListener accepts EWP-over-xhttp (stream-one mode) tunnels.
//
// Wire format: a single long-lived HTTP/2 POST whose request body
// and response body each carry a sequence of length-prefixed (4-byte
// big-endian uint32) v2 messages. Mirrors transport/xhttp/stream_one.go
// on the client side.
//
// listen + path + tlsCfg same semantics as the WS listener. Pass
// tlsCfg=nil to accept h2c (cleartext HTTP/2) — testing only.
func NewXHTTPListener(listen, path string, tlsCfg *tls.Config) Listener {
	if path == "" {
		path = "/"
	}
	return &xhttpListenerAdapter{
		listen: listen,
		path:   path,
		tlsCfg: tlsCfg,
		conns:  make(chan transport.TunnelConn, 32),
	}
}

type xhttpListenerAdapter struct {
	listen string
	path   string
	tlsCfg *tls.Config
	conns  chan transport.TunnelConn

	mu     sync.Mutex
	srv    *http.Server
	closed bool
}

func (x *xhttpListenerAdapter) run(ctx context.Context) {
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc(x.path, x.handleStream)

		srv := &http.Server{
			Addr:      x.listen,
			Handler:   mux,
			TLSConfig: x.tlsCfg,
			// Disable arbitrary deadlines: each tunnel is long-lived.
			ReadTimeout:  0,
			WriteTimeout: 0,
			IdleTimeout:  0,
		}
		// Force HTTP/2 in both TLS and h2c paths.
		_ = http2.ConfigureServer(srv, &http2.Server{})

		x.mu.Lock()
		x.srv = srv
		x.mu.Unlock()

		go func() {
			<-ctx.Done()
			x.Close()
		}()

		var err error
		if x.tlsCfg != nil {
			log.Printf("[ewpserver/xhttp] listening on https://%s%s", x.listen, x.path)
			err = srv.ListenAndServeTLS("", "")
		} else {
			log.Printf("[ewpserver/xhttp] listening on h2c://%s%s (cleartext, tests only)", x.listen, x.path)
			h2s := &http2.Server{}
			srv.Handler = h2c.NewHandler(srv.Handler, h2s)
			ln, lerr := net.Listen("tcp", x.listen)
			if lerr != nil {
				log.Printf("[ewpserver/xhttp] listen: %v", lerr)
				close(x.conns)
				return
			}
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.V("[ewpserver/xhttp] serve: %v", err)
		}
		close(x.conns)
	}()
}

func (x *xhttpListenerAdapter) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming required", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	conn := newXhttpConn(r.Body, w, flusher)
	select {
	case x.conns <- conn:
	case <-r.Context().Done():
		return
	}
	// Hold the handler open. The HTTP/2 stream lives until the engine
	// closes our conn or the client disconnects.
	select {
	case <-conn.done:
	case <-r.Context().Done():
	}
}

func (x *xhttpListenerAdapter) Accept() (transport.TunnelConn, error) {
	c, ok := <-x.conns
	if !ok {
		return nil, errors.New("xhttp listener closed")
	}
	return c, nil
}

func (x *xhttpListenerAdapter) Close() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	x.closed = true
	if x.srv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = x.srv.Shutdown(shutdownCtx)
	}
	return nil
}

func (x *xhttpListenerAdapter) Addr() string {
	if x.tlsCfg != nil {
		return "https://" + x.listen + x.path
	}
	return "h2c://" + x.listen + x.path
}

// xhttpConn is the per-stream TunnelConn carrying length-prefixed
// v2 messages over the request/response body pair.
type xhttpConn struct {
	body    io.Reader
	out     io.Writer
	flusher http.Flusher
	done    chan struct{}

	writeMu sync.Mutex
	once    sync.Once
}

func newXhttpConn(body io.Reader, out io.Writer, f http.Flusher) *xhttpConn {
	return &xhttpConn{body: body, out: out, flusher: f, done: make(chan struct{})}
}

func (c *xhttpConn) SendMessage(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := c.out.Write(hdr[:]); err != nil {
		return err
	}
	if len(b) > 0 {
		if _, err := c.out.Write(b); err != nil {
			return err
		}
	}
	c.flusher.Flush()
	return nil
}

func (c *xhttpConn) ReadMessage() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.body, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, nil
	}
	if n > 16*1024*1024 {
		return nil, errors.New("xhttp: oversized message")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.body, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *xhttpConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
