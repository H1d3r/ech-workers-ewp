package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	commonnet "ewp-core/common/net"
	"ewp-core/internal/server"
	"ewp-core/option"
	pb "ewp-core/proto"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// startFromConfig starts server using configuration file
func startFromConfig(configPath string) {
	// Load configuration
	cfg, err := option.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("❌ Failed to load config: %v", err)
	}

	// Setup logging
	log.SetFlags(log.LstdFlags)
	log.Printf("🚀 EWP-Core Server (Config Mode)")
	log.Printf("📄 Config: %s", configPath)

	// Initialize protocol handler
	if cfg.Protocol.Type == "trojan" {
		log.Printf("🔐 Protocol: Trojan")
		log.Printf("🔑 Password: %s", maskPassword(cfg.Protocol.Password))
		if err := server.InitTrojanHandler(cfg.Protocol.Password); err != nil {
			log.Fatalf("❌ Failed to initialize Trojan handler: %v", err)
		}
		
		// Set fallback if configured
		if cfg.Protocol.Fallback != "" {
			log.Printf("🔄 Fallback: %s", cfg.Protocol.Fallback)
			server.SetTrojanFallback(&TrojanFallbackHandler{addr: cfg.Protocol.Fallback})
		}
	} else {
		log.Printf("🔐 Protocol: EWP")
		log.Printf("🔑 UUID: %s", cfg.Protocol.UUID)
		if cfg.Protocol.EnableFlow {
			log.Printf("🌊 EWP Flow enabled (Vision flow control)")
		}
		if err := server.InitEWPHandler(cfg.Protocol.UUID); err != nil {
			log.Fatalf("❌ Failed to initialize EWP handler: %v", err)
		}
	}

	// Update global state for handler compatibility
	enableFlow = cfg.Protocol.EnableFlow
	trojanMode = cfg.Protocol.Type == "trojan"

	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Printf("🛑 Shutting down...")
		os.Exit(0)
	}()

	// Load TLS config if enabled
	var tlsConfig *tls.Config
	if cfg.TLS != nil && cfg.TLS.Enabled {
		tlsConfig, err = loadTLSConfig(cfg.TLS)
		if err != nil {
			log.Fatalf("❌ Failed to load TLS config: %v", err)
		}
		log.Printf("🔒 TLS enabled (ALPN: %v)", cfg.TLS.ALPN)
	}

	// Check if HTTP/3 is in the modes
	hasH3 := false
	for _, mode := range cfg.Listener.Modes {
		if mode == "h3" {
			hasH3 = true
			break
		}
	}

	// HTTP/3 must run on a separate UDP listener, start it in a goroutine
	if hasH3 {
		go startH3Listener(cfg, tlsConfig)
	}

	// All other modes (ws, grpc, xhttp) can share the same TCP listener
	// Create unified HTTP handler
	mux := createUnifiedHandler(cfg)
	
	addr := fmt.Sprintf("%s:%d", cfg.Listener.Address, cfg.Listener.Port)
	lis, err := commonnet.ListenTFO("tcp", addr)
	if err != nil {
		log.Fatalf("❌ Failed to listen on %s: %v", addr, err)
	}

	httpServer := &http.Server{
		Handler: mux,
	}

	log.Printf("✅ Server listening on %s (modes: %v)", addr, cfg.Listener.Modes)

	if tlsConfig != nil {
		httpServer.TLSConfig = tlsConfig
		log.Fatal(httpServer.ServeTLS(lis, "", ""))
	} else {
		log.Fatal(httpServer.Serve(lis))
	}
}

// createUnifiedHandler creates a unified HTTP handler supporting multiple modes
func createUnifiedHandler(cfg *option.ServerConfig) http.Handler {
	mux := http.NewServeMux()
	
	// Add health endpoints
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)
	
	// Track if we need a default handler
	hasRootHandler := false
	
	// Process each mode
	for _, mode := range cfg.Listener.Modes {
		switch mode {
		case "ws":
			wsPath := cfg.Listener.WSPath
			if wsPath == "" {
				wsPath = "/"
			}
			if wsPath == "/" {
				hasRootHandler = true
			}
			mux.HandleFunc(wsPath, wsHandler)
			log.Printf("📡 WebSocket handler registered (path: %s)", wsPath)
			
		case "grpc":
			// Create gRPC server
			grpcServer := createGRPCServer(cfg)
			
			// Wrap with gRPC-Web adapter if enabled
			var handler http.Handler = grpcServer
			if cfg.Advanced.EnableGRPCWeb {
				handler = server.NewGRPCWebAdapter(grpcServer)
				log.Printf("🌐 gRPC-Web adapter enabled")
			}
			
			// gRPC needs to handle all paths under its service
			serviceName := cfg.Listener.GRPCService
			if serviceName == "" {
				serviceName = "ProxyService"
			}
			grpcPath := "/" + serviceName + "/"
			mux.Handle(grpcPath, handler)
			log.Printf("📡 gRPC handler registered (service: %s)", serviceName)
			
		case "xhttp":
			xhttpPath := cfg.Listener.XHTTPPath
			if xhttpPath == "" {
				xhttpPath = "/xhttp"
			}
			mux.HandleFunc(xhttpPath, xhttpHandler)
			log.Printf("📡 XHTTP handler registered (path: %s)", xhttpPath)
			
		case "h3":
			// HTTP/3 runs on separate UDP listener, skip here
			continue
			
		default:
			log.Printf("⚠️ Unknown mode: %s", mode)
		}
	}
	
	// Add disguise handler for unmatched paths (only if "/" is not already taken)
	if !hasRootHandler {
		mux.HandleFunc("/", disguiseHandler)
	}
	
	return mux
}

// createGRPCServer creates a gRPC server with registered service
func createGRPCServer(cfg *option.ServerConfig) *grpc.Server {
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxConcurrentStreams(1000),
	)

	// Register service
	serviceName := cfg.Listener.GRPCService
	if serviceName == "" {
		serviceName = "ProxyService"
	}

	serviceDesc := &grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*pb.ProxyServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tunnel",
				Handler:       tunnelHandler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "tunnel.proto",
	}
	grpcServer.RegisterService(serviceDesc, &proxyServer{})
	
	return grpcServer
}

// loadTLSConfig loads TLS configuration from server config
func loadTLSConfig(cfg *option.ServerTLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Set ALPN if configured
	if len(cfg.ALPN) > 0 {
		tlsConfig.NextProtos = cfg.ALPN
	}

	return tlsConfig, nil
}

// startH3Listener starts HTTP/3 listener
func startH3Listener(cfg *option.ServerConfig, tlsConfig *tls.Config) {
	if tlsConfig == nil {
		log.Fatalf("❌ HTTP/3 requires TLS to be enabled")
	}

	// Ensure h3 is in ALPN
	hasH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			hasH3 = true
			break
		}
	}
	if !hasH3 {
		log.Fatalf("❌ HTTP/3 requires 'h3' in TLS ALPN")
	}

	// Create gRPC server for HTTP/3
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    60 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)

	// Register service
	serviceName := cfg.Listener.GRPCService
	if serviceName == "" {
		serviceName = "ProxyService"
	}

	serviceDesc := &grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*pb.ProxyServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tunnel",
				Handler:       tunnelHandler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "tunnel.proto",
	}
	grpcServer.RegisterService(serviceDesc, &proxyServer{})

	// Wrap with gRPC-Web adapter (HTTP/3 clients use gRPC-Web format)
	handler := server.NewGRPCWebAdapter(grpcServer)

	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:               20 * time.Second,
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     25 * 1024 * 1024,
	}

	// Create HTTP/3 server
	addr := fmt.Sprintf("%s:%d", cfg.Listener.Address, cfg.Listener.Port)
	h3Server := &http3.Server{
		Addr:       addr,
		Handler:    handler,
		TLSConfig:  tlsConfig,
		QUICConfig: quicConfig,
	}

	log.Printf("✅ HTTP/3 listening on %s (service: %s)", addr, serviceName)
	log.Printf("🌐 gRPC-Web over HTTP/3 enabled")

	if err := h3Server.ListenAndServe(); err != nil {
		log.Fatalf("❌ HTTP/3 server failed: %v", err)
	}
}
