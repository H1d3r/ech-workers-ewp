package cfg

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"ewp-core/engine"
	"ewp-core/inbound/ewpserver"
	"ewp-core/transport"
)

// buildEWPServerInbound constructs an ewpserver.Inbound from a YAML
// inbound block. Currently only the WebSocket transport is supported
// for the server side; gRPC / HTTP-3 / xhttp listeners are
// follow-ups (the heavy lifting is the per-transport HTTP/2 or
// QUIC server scaffolding, not the EWP layer).
func buildEWPServerInbound(c InboundCfg) (engine.Inbound, error) {
	uuids, err := parseUUIDs(c.UUIDs)
	if err != nil {
		return nil, fmt.Errorf("ewpserver %q: %w", c.Tag, err)
	}
	tlsCfg, err := buildServerTLSConfig(c.Transport)
	if err != nil {
		return nil, fmt.Errorf("ewpserver %q: tls: %w", c.Tag, err)
	}
	listen := c.Transport.URL
	if listen == "" {
		listen = c.Listen
	}
	if listen == "" {
		return nil, errors.New("ewpserver: transport.url or listen is required")
	}
	path := c.Transport.Path
	if path == "" {
		path = "/"
	}
	uuids16 := make([][16]byte, len(uuids))
	for i, u := range uuids {
		uuids16[i] = u
	}

	var ln ewpserver.Listener
	switch c.Transport.Kind {
	case "ws", "websocket":
		ln = ewpserver.NewWSListenerWithTLS(listen, path, tlsCfg)
	case "grpc":
		ln = ewpserver.NewGRPCListener(listen, tlsCfg)
	case "h3", "h3grpc":
		if tlsCfg == nil {
			return nil, errors.New("ewpserver: h3 requires TLS (cert + key)")
		}
		ln = ewpserver.NewH3Listener(listen, path, tlsCfg)
	case "xhttp":
		ln = ewpserver.NewXHTTPListener(listen, path, tlsCfg)
	default:
		return nil, fmt.Errorf("ewpserver %q: unsupported transport kind %q", c.Tag, c.Transport.Kind)
	}
	return ewpserver.New(c.Tag, ln, uuids16)
}

// buildServerTLSConfig loads the TLS keypair from disk. Returns
// (nil, nil) if no cert/key configured (plaintext mode, tests only).
func buildServerTLSConfig(t TransportCfg) (*tls.Config, error) {
	if t.CertFile == "" && t.KeyFile == "" {
		return nil, nil
	}
	if t.CertFile == "" || t.KeyFile == "" {
		return nil, errors.New("both cert and key must be set together")
	}
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(t.CertFile); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	return cfg, nil
}

// wsAdapter is an internal Listener that wraps the package-private
// run-loop semantics of ewpserver.WSListenerAdapter without forcing
// cfg/ to import implementation details.
type wsAdapter struct {
	listen string
	path   string
	tlsCfg *tls.Config

	// Filled in on first Accept() to defer construction until
	// Inbound.Start runs (i.e. after the engine is wired).
	inner ewpserverListener
}

// ewpserverListener is the same as ewpserver.Listener but kept
// private here.
type ewpserverListener interface {
	Accept() (transport.TunnelConn, error)
	Close() error
	Addr() string
}

func newWSAdapter(listen, path string, tlsCfg *tls.Config) *wsAdapter {
	return &wsAdapter{listen: listen, path: path, tlsCfg: tlsCfg}
}

// Accept lazily creates and starts the underlying WSListener on
// first call so we can defer all socket binding until the engine has
// invoked Start.
func (a *wsAdapter) Accept() (transport.TunnelConn, error) {
	if a.inner == nil {
		ad := ewpserver.NewWSListenerWithTLS(a.listen, a.path, a.tlsCfg)
		a.inner = ad
	}
	return a.inner.Accept()
}

func (a *wsAdapter) Close() error {
	if a.inner != nil {
		return a.inner.Close()
	}
	return nil
}

func (a *wsAdapter) Addr() string {
	if a.tlsCfg != nil {
		return "wss://" + a.listen + a.path
	}
	return "ws://" + a.listen + a.path
}
