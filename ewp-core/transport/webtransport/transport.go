package webtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/quic-go/quic-go"
	wtransport "github.com/quic-go/webtransport-go"
)

// Transport implements transport.Transport over WebTransport (QUIC + HTTP/3 + EWP).
//
// A single QUIC connection (webtransport.Session) is shared across all Dial()
// calls: each Dial() opens a new bidi stream on the existing session.
// When the session breaks it is transparently replaced on the next Dial().
type Transport struct {
	serverAddr   string // "host:port"
	path         string // HTTP path, e.g. "/wt"
	uuid         [16]byte
	sni          string
	useECH       bool
	enablePQC    bool
	useMozillaCA bool
	echManager   *commontls.ECHManager
	idleTimeout  time.Duration
	bypassCfg    *transport.BypassConfig

	mu         sync.Mutex
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	dialer     *wtransport.Dialer
	sess       *wtransport.Session
}

// New creates a WebTransport client transport.
//
// serverAddr is "host:port" or "https://host:port/path".
// path is the WebTransport endpoint path (default "/wt").
// echManager may be nil when ECH is disabled.
func New(serverAddr, uuidStr string, useECH, useMozillaCA, enablePQC bool, path string, echManager *commontls.ECHManager) (*Transport, error) {
	uuid, err := transport.ParseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid UUID: %w", err)
	}

	parsed, err := transport.ParseAddress(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	if path == "" {
		if parsed.Path != "" && parsed.Path != "/" {
			path = parsed.Path
		} else {
			path = "/wt"
		}
	}

	addr := net.JoinHostPort(parsed.Host, parsed.Port)

	t := &Transport{
		serverAddr:   addr,
		path:         path,
		uuid:         uuid,
		useECH:       useECH,
		useMozillaCA: useMozillaCA,
		enablePQC:    enablePQC,
		echManager:   echManager,
		idleTimeout:  30 * time.Second,
	}

	if err := t.initDialer(); err != nil {
		return nil, err
	}
	return t, nil
}

// initDialer builds TLS + QUIC config and creates the webtransport.Dialer.
// Must be called with mu held (or during construction before the Transport escapes).
func (t *Transport) initDialer() error {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return fmt.Errorf("parse server address: %w", err)
	}

	serverName := t.sni
	if serverName == "" {
		serverName = parsed.Host
	}

	tlsCfg, err := commontls.NewClient(commontls.ClientOptions{
		ServerName:   serverName,
		UseMozillaCA: t.useMozillaCA,
		EnableECH:    t.useECH,
		EnablePQC:    t.enablePQC,
		ECHManager:   t.echManager,
	})
	if err != nil {
		return fmt.Errorf("create TLS config: %w", err)
	}

	stdTLS, err := tlsCfg.TLSConfig()
	if err != nil {
		return fmt.Errorf("get TLS config: %w", err)
	}

	stdTLS.NextProtos = []string{"h3"}
	stdTLS.ClientSessionCache = tls.NewLRUClientSessionCache(64)

	t.tlsConfig = stdTLS

	t.quicConfig = &quic.Config{
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     25 * 1024 * 1024,
		MaxIdleTimeout:                 t.idleTimeout,
		KeepAlivePeriod:                10 * time.Second,
		EnableDatagrams:                true, // required by WebTransport spec
		Allow0RTT:                      true,
	}

	d := &wtransport.Dialer{
		TLSClientConfig: t.tlsConfig,
		QUICConfig:      t.quicConfig,
	}

	if t.bypassCfg != nil && t.bypassCfg.UDPListenConfig != nil {
		d.DialAddr = t.makeBypassDial(t.bypassCfg.UDPListenConfig)
	}

	t.dialer = d
	return nil
}

// makeBypassDial returns a DialAddr function that binds the QUIC UDP socket
// to the physical network interface, bypassing the TUN routing table.
func (t *Transport) makeBypassDial(lc *net.ListenConfig) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("bypass dial: resolve %s: %w", addr, err)
		}
		pconn, err := lc.ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, fmt.Errorf("bypass dial: bind UDP: %w", err)
		}
		qt := &quic.Transport{Conn: pconn}
		conn, err := qt.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		if err != nil {
			qt.Close()
			return nil, fmt.Errorf("bypass dial: QUIC: %w", err)
		}
		return conn, nil
	}
}

// Name returns a descriptive transport name.
func (t *Transport) Name() string {
	name := "WebTransport+EWP"
	if t.useECH {
		name += "+ECH"
	}
	if t.enablePQC {
		name += "+PQC"
	}
	return name
}

// SetSNI overrides the TLS SNI (useful when connecting via IP with CDN domain).
func (t *Transport) SetSNI(sni string) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sni = sni
	t.reinitDialer()
	return t
}

// SetIdleTimeout sets the QUIC connection idle timeout.
func (t *Transport) SetIdleTimeout(d time.Duration) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.idleTimeout = d
	if t.quicConfig != nil {
		t.quicConfig.MaxIdleTimeout = d
	}
	return t
}

// SetBypassConfig injects a bypass dialer for TUN mode.
func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bypassCfg = cfg
	t.reinitDialer()
}

// reinitDialer must be called with mu held.
func (t *Transport) reinitDialer() {
	// Invalidate current session so next Dial() reconnects with new settings.
	t.sess = nil
	if err := t.initDialer(); err != nil {
		log.Printf("[WebTransport] Failed to reinit dialer: %v", err)
	}
}

// Dial opens a new bidi stream on the shared WebTransport session,
// reconnecting transparently if the session has died.
func (t *Transport) Dial() (transport.TunnelConn, error) {
	stream, err := t.openStream()
	if err != nil {
		return nil, err
	}
	return newConn(stream, t.uuid), nil
}

func (t *Transport) openStream() (*wtransport.Stream, error) {
	t.mu.Lock()
	sess := t.sess
	t.mu.Unlock()

	if sess != nil {
		stream, err := sess.OpenStreamSync(context.Background())
		if err == nil {
			return stream, nil
		}
		log.V("[WebTransport] Session broken (%v), reconnecting", err)
		t.mu.Lock()
		t.sess = nil
		t.mu.Unlock()
	}

	sess, err := t.connect()
	if err != nil {
		return nil, err
	}

	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		return nil, fmt.Errorf("open stream after reconnect: %w", err)
	}
	return stream, nil
}

func (t *Transport) connect() (*wtransport.Session, error) {
	t.mu.Lock()
	dialer := t.dialer
	t.mu.Unlock()

	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	// Resolve hostname to IP (avoids TUN routing loops and picks best edge node).
	host := parsed.Host
	port := parsed.Port
	if !isIPAddress(host) {
		resolved, err := transport.ResolveIP(t.bypassCfg, host, port)
		if err != nil {
			log.Printf("[WebTransport] DNS resolve failed for %s: %v", host, err)
			return nil, fmt.Errorf("DNS resolve: %w", err)
		}
		log.V("[WebTransport] Resolved %s -> %s", host, resolved)
		host = resolved
	}

	// Build the WebTransport URL. Use the original hostname as authority so
	// TLS SNI and virtual hosting work correctly even when connecting via IP.
	authority := net.JoinHostPort(parsed.Host, port)
	connectAddr := fmt.Sprintf("https://%s%s", authority, t.path)
	if host != parsed.Host {
		// Override Host header with the authority (original domain) while
		// connecting to the resolved IP.
		connectAddr = fmt.Sprintf("https://%s%s", net.JoinHostPort(host, port), t.path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hdr := http.Header{}
	if host != parsed.Host {
		hdr.Set("Host", authority)
	}

	log.V("[WebTransport] Connecting to %s (path: %s)", connectAddr, t.path)
	_, sess, err := dialer.Dial(ctx, connectAddr, hdr)
	if err != nil {
		// Handle ECH rejection: update key and retry once.
		if retryErr := t.handleECHRejection(err); retryErr == nil {
			t.mu.Lock()
			dialer = t.dialer
			t.mu.Unlock()
			ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel2()
			_, sess, err = dialer.Dial(ctx2, connectAddr, hdr)
		}
		if err != nil {
			return nil, fmt.Errorf("webtransport dial: %w", err)
		}
	}

	t.mu.Lock()
	t.sess = sess
	t.mu.Unlock()

	log.V("[WebTransport] Session established to %s", t.serverAddr)
	return sess, nil
}

// handleECHRejection extracts the server's ECH retry config, updates the
// ECH manager, and rebuilds the dialer.  Returns nil on success (caller retries).
func (t *Transport) handleECHRejection(err error) error {
	if !t.useECH || t.echManager == nil {
		return errors.New("ECH not enabled or no manager")
	}

	var echRejErr *tls.ECHRejectionError
	if !errors.As(err, &echRejErr) {
		return errors.New("not an ECH rejection error")
	}

	retryList := echRejErr.RetryConfigList
	if len(retryList) == 0 {
		log.Printf("[WebTransport] ECH rejected with empty retry list")
		return errors.New("empty retry config")
	}

	log.Printf("[WebTransport] ECH rejected; updating config (%d bytes)", len(retryList))

	if err := t.echManager.UpdateFromRetry(retryList); err != nil {
		return fmt.Errorf("update ECH config: %w", err)
	}

	t.mu.Lock()
	t.reinitDialer()
	t.mu.Unlock()

	log.Printf("[WebTransport] ECH config updated; retrying")
	return nil
}

// isIPAddress reports whether s is a valid IP address (not a hostname).
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
