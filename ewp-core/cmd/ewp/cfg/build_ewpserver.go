package cfg

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"ewp-core/engine"
	"ewp-core/inbound/ewpserver"
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
	copy(uuids16, uuids)

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

// (wsAdapter / ewpserverListener / newWSAdapter were removed: they
// were superseded by direct use of ewpserver.NewWSListenerWithTLS
// from buildEWPServerInbound and never referenced.)
