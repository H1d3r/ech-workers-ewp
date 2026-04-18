package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	commontls "ewp-core/common/tls"
	"ewp-core/constant"
	"ewp-core/log"
	"ewp-core/option"
	"ewp-core/protocol"
	"ewp-core/protocol/socks5"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/h3grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
	"ewp-core/tun"
	"ewp-core/tun/util"
)

// P2-25: Global state for hot reload
var (
	currentServer   atomic.Value // stores *protocol.Server
	currentTransport atomic.Value // stores transport.Transport
	currentECHMgr   atomic.Value // stores *commontls.ECHManager
	reloadMutex     sync.Mutex
	configPath      string
)

func main() {
	// Load configuration (will parse flags internally)
	cfg, err := option.LoadConfigWithFallback()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		fmt.Fprintf(os.Stderr, "Usage: %s -c config.json\n", os.Args[0])
		os.Exit(1)
	}

	// P2-25: Save config path for hot reload
	configPath = option.GetConfigPath()

	// Setup logging
	setupLogging(cfg)

	log.Info("EWP-Core Client")
	log.Info("Config: Inbounds=%d, Outbounds=%d", len(cfg.Inbounds), len(cfg.Outbounds))

	// Get the first outbound (primary proxy)
	if len(cfg.Outbounds) == 0 {
		log.Fatalf("No outbound configured")
	}

	outbound := cfg.Outbounds[0]
	log.Info("Outbound: tag=%s, type=%s, server=%s:%d",
		outbound.Tag, outbound.Type, outbound.Server, outbound.ServerPort)

	// Create transport (and get echMgr and dohServers for TUN bypass injection)
	trans, echMgr, dohServers, err := createTransport(outbound, cfg)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	// Determine inbound type
	if len(cfg.Inbounds) == 0 {
		log.Fatalf("No inbound configured")
	}

	inbound := cfg.Inbounds[0]
	log.Info("Inbound: tag=%s, type=%s", inbound.Tag, inbound.Type)

	// P2-25: Setup SIGHUP handler for hot reload (proxy mode only)
	// TUN mode doesn't support hot reload due to network interface complexity
	if inbound.Type != "tun" {
		setupSIGHUPHandler()
	}

	// Start based on inbound type
	switch inbound.Type {
	case "tun":
		startTunMode(inbound, trans, echMgr, dohServers, cfg)
	case "mixed", "socks", "http":
		startProxyMode(inbound, trans, cfg)
	default:
		log.Fatalf("Unsupported inbound type: %s", inbound.Type)
	}
}

// bypassDialerProvider is implemented by transport types that expose their
// bypass dialer (set by tun.Setup) so the ECH manager can use it too.
type bypassDialerProvider interface {
	BypassDialer() *net.Dialer
}

func createTransport(outbound option.OutboundConfig, cfg *option.RootConfig) (transport.Transport, *commontls.ECHManager, []string, error) {
	// Validate outbound
	if outbound.Type != "ewp" && outbound.Type != "trojan" {
		return nil, nil, nil, fmt.Errorf("unsupported outbound type: %s", outbound.Type)
	}

	// Determine server address
	serverAddr := net.JoinHostPort(outbound.Server, fmt.Sprint(outbound.ServerPort))

	// Determine authentication
	var uuid, password string
	useTrojan := outbound.Type == "trojan"

	if useTrojan {
		password = outbound.Password
		log.Info("Protocol: Trojan")
	} else {
		uuid = outbound.UUID
		log.Info("Protocol: EWP (UUID: %s)", uuid)
	}

	// Initialize ECH manager
	var echMgr *commontls.ECHManager
	var dohServers []string // DoH servers for both ECH and BypassResolver
	useECH := outbound.TLS != nil && outbound.TLS.ECH != nil && outbound.TLS.ECH.Enabled

	if useECH {
		echDomain := outbound.TLS.ECH.ConfigDomain
		dohServers = outbound.TLS.ECH.DOHServers // P0-12: multiple servers
		strictMode := !outbound.TLS.ECH.FallbackOnError // P0-12: strict mode

		if echDomain == "" {
			echDomain = "cloudflare-ech.com"
		}
		
		// P0-12: backward compatibility - if DOHServers is empty but DOHServer is set, use it
		if len(dohServers) == 0 && outbound.TLS.ECH.DOHServer != "" {
			dohServers = []string{outbound.TLS.ECH.DOHServer}
		}
		
		if len(dohServers) == 0 {
			// P0-12: use multiple default servers for redundancy
			dohServers = constant.DefaultDNSServers
		}

		log.Info("ECH: initializing (domain: %s, DoH servers: %v, strict: %v)", 
			echDomain, dohServers, strictMode)
		echMgr = commontls.NewECHManagerWithTTL(echDomain, 1*time.Hour, strictMode, dohServers...)

		if err := echMgr.Refresh(); err != nil {
			if outbound.TLS.ECH.FallbackOnError {
				log.Warn("ECH initialization failed, falling back to plain TLS: %v", err)
				useECH = false
				echMgr = nil
			} else {
				return nil, nil, nil, fmt.Errorf("ECH initialization failed: %w", err)
			}
		}
	} else {
		// Even without ECH, use default DoH servers for BypassResolver
		dohServers = constant.DefaultDNSServers
	}

	// Get transport config
	if outbound.Transport == nil {
		return nil, nil, nil, fmt.Errorf("transport configuration is required")
	}

	transportType := outbound.Transport.Type
	enableFlow := outbound.Flow != nil && outbound.Flow.Enabled
	enablePQC := outbound.TLS != nil && outbound.TLS.PQC
	useMozillaCA := outbound.TLS != nil && outbound.TLS.UseMozillaCA

	log.Info("Transport: type=%s, flow=%v, ECH=%v, PQC=%v, MozillaCA=%v",
		transportType, enableFlow, useECH, enablePQC, useMozillaCA)

	// Create transport based on type
	var trans transport.Transport
	var err error

	switch transportType {
	case "ws":
		path := outbound.Transport.Path
		if path == "" {
			path = "/"
		}
		trans, err = websocket.NewWithProtocol(
			serverAddr, uuid, password,
			useECH, useMozillaCA, enableFlow, enablePQC, useTrojan,
			path, echMgr,
		)
		if err != nil {
			return nil, nil, nil, err
		}

	case "grpc":
		serviceName := outbound.Transport.ServiceName
		if serviceName == "" {
			serviceName = "ProxyService"
		}
		grpcTrans, err := grpc.NewWithProtocol(
			serverAddr, uuid, password,
			useECH, useMozillaCA, enableFlow, enablePQC, useTrojan,
			serviceName, echMgr,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		if outbound.Transport.UserAgent != "" {
			grpcTrans.SetUserAgent(outbound.Transport.UserAgent)
		}
		trans = grpcTrans

	case "h3grpc":
		serviceName := outbound.Transport.ServiceName
		if serviceName == "" {
			serviceName = "ProxyService"
		}
		h3Trans, err := h3grpc.NewWithProtocol(
			serverAddr, uuid, password,
			useECH, useMozillaCA, enableFlow, enablePQC, useTrojan,
			serviceName, echMgr,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		if outbound.Transport.UserAgent != "" {
			h3Trans.SetUserAgent(outbound.Transport.UserAgent)
		}
		if outbound.Transport.ContentType != "" {
			h3Trans.SetContentType(outbound.Transport.ContentType)
		}
		trans = h3Trans

	case "xhttp":
		path := outbound.Transport.Path
		if path == "" {
			path = "/xhttp"
		}
		trans, err = xhttp.NewWithProtocol(
			serverAddr, uuid, password,
			useECH, useMozillaCA, enableFlow, enablePQC, useTrojan,
			path, echMgr,
		)
		if err != nil {
			return nil, nil, nil, err
		}

	default:
		return nil, nil, nil, fmt.Errorf("unsupported transport type: %s", transportType)
	}

	// Apply Host override (HTTP Host header / gRPC authority)
	if outbound.Host != "" {
		switch t := trans.(type) {
		case *websocket.Transport:
			t.SetHost(outbound.Host)
		case *grpc.Transport:
			t.SetAuthority(outbound.Host)
		case *h3grpc.Transport:
			t.SetAuthority(outbound.Host)
		case *xhttp.Transport:
			t.SetHost(outbound.Host)
		}
	}

	// Apply SNI override: tls.server_name → host → "" (transport falls back to parsed server host)
	effectiveSNI := ""
	if outbound.TLS != nil {
		effectiveSNI = outbound.TLS.ServerName
	}
	if effectiveSNI == "" {
		effectiveSNI = outbound.Host
	}
	if effectiveSNI != "" {
		switch t := trans.(type) {
		case *websocket.Transport:
			t.SetSNI(effectiveSNI)
		case *grpc.Transport:
			t.SetSNI(effectiveSNI)
		case *h3grpc.Transport:
			// P2-11: h3grpc SetSNI now returns error
			if err := t.SetSNI(effectiveSNI); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to set SNI: %w", err)
			}
		case *xhttp.Transport:
			t.SetSNI(effectiveSNI)
		}
	}

	log.Info("Transport created: %s", trans.Name())
	return trans, echMgr, dohServers, nil
}

func startTunMode(inbound option.InboundConfig, trans transport.Transport, echMgr *commontls.ECHManager, dohServers []string, cfg *option.RootConfig) {
	log.Info("Starting TUN mode...")

	if !util.IsAdmin() {
		log.Fatalf("TUN mode requires administrator privileges")
	}

	// Parse TUN address
	tunIP := inbound.Inet4Address
	if tunIP == "" {
		tunIP = "10.0.85.2/24"
	}

	// Parse TUN IPv6 address (dual-stack enabled by default)
	tunIPv6 := inbound.Inet6Address
	if tunIPv6 == "" {
		tunIPv6 = "fd00:5ca1:e::2/64" // Default IPv6 ULA address
	}

	mtu := inbound.MTU
	if mtu == 0 {
		mtu = 1380
	}

	// Determine DNS servers for TUN mode (dual-stack)
	// All DNS traffic will be routed through the proxy tunnel automatically
	dnsServer := inbound.DNS
	if dnsServer == "" {
		dnsServer = "8.8.8.8" // Default to Google Public DNS (IPv4)
	}

	// IPv6 DNS server - must be a real public address (not virtual)
	dns6Server := inbound.IPv6DNS
	if dns6Server == "" {
		dns6Server = "2001:4860:4860::8888" // Default to Google Public DNS (IPv6)
	}

	log.Info("TUN DNS: IPv4=%s, IPv6=%s", dnsServer, dns6Server)

	tunCfg := &tun.Config{
		IP:               tunIP,
		DNS:              dnsServer,
		IPv6:             tunIPv6,
		IPv6DNS:          dns6Server,
		MTU:              mtu,
		Stack:            inbound.Stack,
		Transport:        trans,
		ServerAddr:       cfg.Outbounds[0].Server,
		TunnelDoHServer:  inbound.TunnelDoHServer,
		BypassDoHServers: dohServers, // Use same DoH servers as ECH config
	}

	tunDev, err := tun.New(tunCfg)
	if err != nil {
		log.Fatalf("TUN initialization failed: %v", err)
	}
	defer tunDev.Close()

	// Setup MUST be called before Start():
	// 1. detects the physical outbound interface and installs a bypass dialer on
	//    the transport (while the physical default route is still in place)
	// 2. assigns the TUN IP address and adds the default 0.0.0.0/0 route through
	//    the TUN device (which would redirect the probe in step 1 if done first)
	if err := tunDev.Setup(); err != nil {
		log.Fatalf("TUN setup failed: %v", err)
	}

	// P1-1: After TUN setup the physical bypass dialer is installed on the
	// transport. Inject it into the ECH manager so that background ECH
	// refreshes (every ~1h) route via the physical NIC, not through TUN.
	// Without this, the refresh triggers a DNS lookup → TUN → proxy →
	// needs ECH → deadlock.
	if echMgr != nil {
		if provider, ok := trans.(bypassDialerProvider); ok {
			if d := provider.BypassDialer(); d != nil {
				echMgr.SetBypassDialer(d)
				log.Info("[ECH] TUN bypass dialer injected — background refreshes bypass TUN")
			}
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	go func() {
		<-sigChan
		log.Info("Received exit signal, shutting down TUN...")
		tunDev.Close()
	}()

	if err := tunDev.Start(); err != nil {
		log.Printf("[TUN] TUN mode stopped: %v", err)
	}
}

func startProxyMode(inbound option.InboundConfig, trans transport.Transport, cfg *option.RootConfig) {
	listenAddr := inbound.Listen
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}

	log.Info("Starting %s proxy on %s", inbound.Type, listenAddr)

	// Determine DNS server for protocol module
	// Use IP address to avoid DNS dependency (Alibaba Cloud DNS)
	dnsServer := "https://223.5.5.5/dns-query"
	if cfg.DNS != nil && cfg.DNS.Final != "" {
		for _, server := range cfg.DNS.Servers {
			if server.Tag == cfg.DNS.Final {
				dnsServer = server.Address
				break
			}
		}
	}

	// Build user auth map from inbound config.
	var users socks5.Users
	if len(inbound.Users) > 0 {
		users = make(socks5.Users, len(inbound.Users))
		for _, u := range inbound.Users {
			users[u.Username] = u.Password
		}
		log.Info("SOCKS5 auth enabled (%d user(s))", len(users))
	}

	// P2-25: Store transport for hot reload
	currentTransport.Store(trans)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Received exit signal, shutting down...")
		os.Exit(0)
	}()

	server := protocol.NewServer(listenAddr, trans, dnsServer, users, inbound.MaxConnections)
	
	// P2-25: Store server for hot reload
	currentServer.Store(server)
	
	log.Fatalf("Proxy server stopped: %v", server.Run())
}

func setupLogging(cfg *option.RootConfig) {
	// Set log level
	verbose := cfg.Log.Level == "debug"
	log.SetVerbose(verbose)

	// Set log file if specified
	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		log.SetMultiOutput(os.Stdout, f)
	}
}

// P2-25: Setup SIGHUP handler for configuration hot reload
func setupSIGHUPHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	
	go func() {
		for range sigChan {
			log.Info("[RELOAD] Received SIGHUP signal, reloading configuration...")
			if err := reloadConfig(); err != nil {
				log.Warn("[RELOAD] Configuration reload failed: %v", err)
			} else {
				log.Info("[RELOAD] Configuration reloaded successfully")
			}
		}
	}()
	
	log.Info("[RELOAD] SIGHUP handler installed (send SIGHUP to reload config)")
}

// P2-25: Reload configuration and recreate transport
// Existing connections continue to use old transport, new connections use new transport
func reloadConfig() error {
	reloadMutex.Lock()
	defer reloadMutex.Unlock()
	
	// Load new configuration
	cfg, err := option.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	
	// Validate configuration
	if len(cfg.Outbounds) == 0 {
		return fmt.Errorf("no outbound configured")
	}
	if len(cfg.Inbounds) == 0 {
		return fmt.Errorf("no inbound configured")
	}
	
	outbound := cfg.Outbounds[0]
	inbound := cfg.Inbounds[0]
	
	// TUN mode doesn't support hot reload
	if inbound.Type == "tun" {
		return fmt.Errorf("TUN mode does not support hot reload")
	}
	
	log.Info("[RELOAD] Creating new transport: %s → %s:%d", 
		outbound.Type, outbound.Server, outbound.ServerPort)
	
	// Create new transport
	newTrans, newECHMgr, _, err := createTransport(outbound, cfg)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}
	
	// Get old transport and ECH manager for cleanup
	_, _ = currentTransport.Load().(transport.Transport)
	oldECHMgr, _ := currentECHMgr.Load().(*commontls.ECHManager)
	
	// Store new transport and ECH manager
	currentTransport.Store(newTrans)
	currentECHMgr.Store(newECHMgr)
	
	// Get current server and update its transport
	if srv, ok := currentServer.Load().(*protocol.Server); ok {
		srv.UpdateTransport(newTrans)
		log.Info("[RELOAD] Server transport updated")
	}
	
	// Cleanup old resources after a grace period
	// Give existing connections time to complete
	go func() {
		time.Sleep(30 * time.Second)
		
		if oldECHMgr != nil {
			// P1-6: Stop ECH manager to release resources
			oldECHMgr.Stop()
			log.Info("[RELOAD] Old ECH manager stopped")
		}
		
		// Note: We don't close oldTrans here because existing connections may still be using it
		// The transport will be garbage collected when all connections are closed
		log.Info("[RELOAD] Old transport cleanup scheduled")
	}()
	
	// Update logging if changed
	setupLogging(cfg)
	
	return nil
}
