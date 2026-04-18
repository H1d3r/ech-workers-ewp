package constant

// Transport modes
const (
	TransportWebSocket = "ws"
	TransportGRPC      = "grpc"
	TransportXHTTP     = "xhttp"
)

// DNS record types
const (
	TypeHTTPS uint16 = 65
)

// Default values
const (
	DefaultListenAddr = "127.0.0.1:30000"
	DefaultECHDomain  = "cloudflare-ech.com"
	DefaultNumConns   = 1
	DefaultXHTTPMode  = "auto"
	DefaultTunIP      = "10.0.85.2"
	DefaultTunGateway = "10.0.85.1"
	DefaultTunMask    = "255.255.255.0"
	DefaultTunDNS     = "1.1.1.1"
	DefaultTunMTU     = 1380
)

// P0-12: Multiple DoH servers for redundancy and race-to-fastest.
// Using China-friendly servers to avoid blocking issues with Google/Cloudflare.
// Servers are tried in parallel; the first successful response wins.
// Users can override these by setting custom DOHServers in config.
var DefaultDNSServers = []string{
	"https://223.5.5.5/dns-query",   // Aliyun DNS (primary)
	"https://223.6.6.6/dns-query",   // Aliyun DNS (secondary)
	"https://doh.pub/dns-query",     // DNSPod (Tencent)
}

// Deprecated: Use DefaultDNSServers instead. Kept for backward compatibility.
const DefaultDNSServer = "https://223.5.5.5/dns-query"

// Buffer sizes
const (
	SmallBufferSize = 512
	LargeBufferSize = 32 * 1024
	UDPBufferSize   = 65536
)

// Timeouts
const (
	DefaultDialTimeout      = 10 // seconds
	DefaultHandshakeTimeout = 10 // seconds
)
