package tun

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	commpool "ewp-core/common/bufferpool"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// udpSessionKey identifies a unique UDP flow: one local socket sending to one destination.
// Using (src, dst) instead of src-only enables correct per-destination fakeAddr tracking,
// which is required for NAT type detection tools that send from the same local port to
// multiple different servers and expect responses from each server's own address.
type udpSessionKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// udpSession represents a proxy tunnel connection for a specific (src, dst) UDP flow.
type udpSession struct {
	tunnelConn transport.TunnelConn
	remoteAddr netip.AddrPort // the remote server addr (responses appear to come FROM here)
	fakeAddr   netip.AddrPort // FakeIP:Port the client sent to — injected back as response src
	lastActive atomic.Int64  // UnixNano; updated on every packet, read by cleanup goroutine
}

// UDPWriter allows the handler to write responses back to the TUN virtual device
type UDPWriter interface {
	WriteTo(p []byte, src netip.AddrPort, dst netip.AddrPort) error
	InjectUDP(p []byte, src netip.AddrPort, dst netip.AddrPort) error
	ReleaseConn(src netip.AddrPort, dst netip.AddrPort)
}

type Handler struct {
	transport  transport.Transport
	ctx        context.Context
	fakeIPPool *dns.FakeIPPool

	udpWriter   UDPWriter
	udpSessions sync.Map // map[netip.AddrPort]*udpSession
}

func NewHandler(ctx context.Context, trans transport.Transport, udpWriter UDPWriter) *Handler {
	h := &Handler{
		transport: trans,
		ctx:       ctx,
		udpWriter: udpWriter,
	}

	// Start UDP Session Cleanup coroutine (Full Cone NAT state tracking)
	go h.cleanupUDPSessions()

	return h
}

// SetFakeIPPool sets the FakeIP pool for instant DNS responses.
func (h *Handler) SetFakeIPPool(pool *dns.FakeIPPool) {
	h.fakeIPPool = pool
}

func (h *Handler) HandleTCP(conn *gonet.TCPConn) {
	dstAddr := conn.LocalAddr().(*net.TCPAddr)
	srcAddr := conn.RemoteAddr().(*net.TCPAddr)

	// If destination is a fake IP, reverse-lookup the domain for Connect
	var target string
	if h.fakeIPPool != nil {
		dstIP, _ := netip.AddrFromSlice(dstAddr.IP)
		dstIP = dstIP.Unmap() // convert ::ffff:198.18.x.x → 198.18.x.x
		if domain, ok := h.fakeIPPool.LookupByIP(dstIP); ok {
			target = net.JoinHostPort(domain, strconv.Itoa(dstAddr.Port))
			log.Printf("[TUN TCP] FakeIP reverse: %s -> %s", dstAddr, target)
		} else if h.fakeIPPool.IsFakeIP(dstIP) {
			log.Printf("[TUN TCP] WARNING: FakeIP %s has no mapping!", dstIP)
		}
	}
	if target == "" {
		target = dstAddr.String()
	}
	log.Printf("[TUN TCP] New connection: %s -> %s", srcAddr, target)

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		log.Printf("[TUN TCP] Tunnel dial failed: %v", err)
		conn.Close()
		return
	}
	defer tunnelConn.Close()
	defer conn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.Connect(target, nil); err != nil {
		log.Printf("[TUN TCP] CONNECT failed: %v", err)
		return
	}

	log.V("[TUN TCP] Connected: %s", target)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b := commpool.GetLarge()
		defer commpool.PutLarge(b)
		for {
			n, err := conn.Read(b)
			if err != nil {
				tunnelConn.Close()
				return
			}
			if err := tunnelConn.Write(b[:n]); err != nil {
				conn.Close()
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		b := commpool.GetLarge()
		defer commpool.PutLarge(b)
		for {
			n, err := tunnelConn.Read(b)
			if err != nil {
				conn.Close()
				return
			}
			if _, err := conn.Write(b[:n]); err != nil {
				tunnelConn.Close()
				return
			}
		}
	}()

	wg.Wait()
	log.V("[TUN TCP] Disconnected: %s", target)
}

func (h *Handler) HandleUDP(payload []byte, src netip.AddrPort, dst netip.AddrPort) {
	log.V("[TUN UDP] HandleUDP: src=%s dst=%s payload_len=%d", src, dst, len(payload))

	// DNS interception: use FakeIP for instant response
	if dst.Port() == 53 && h.fakeIPPool != nil {
		h.handleDNSFakeIP(payload, src, dst)
		return
	}

	// Reverse-lookup fake IP to domain for UDP endpoint.
	// dst is always a FakeIP in TUN mode (gVisor only sees IPs).
	var endpoint transport.Endpoint
	if h.fakeIPPool != nil {
		unmapped := dst.Addr().Unmap()
		if domain, ok := h.fakeIPPool.LookupByIP(unmapped); ok {
			endpoint = transport.Endpoint{Domain: domain, Port: dst.Port()}
			log.Printf("[TUN UDP] FakeIP reverse: %s -> %s:%d", dst, domain, dst.Port())
		}
	}
	if endpoint.Domain == "" && !endpoint.Addr.IsValid() {
		endpoint = transport.Endpoint{Addr: dst}
	}

	// Session key is (src, dst): each unique local-port → destination pair gets its
	// own tunnel and fakeAddr. This is required for NAT detection tools that send
	// from the same local port to multiple servers and expect per-server responses.
	key := udpSessionKey{src: src, dst: dst}
	val, ok := h.udpSessions.Load(key)
	var session *udpSession

	if !ok {
		tunnelConn, err := h.transport.Dial()
		if err != nil {
			log.Printf("[TUN UDP] Tunnel dial failed for %s->%s: %v", src, dst, err)
			return
		}

		session = &udpSession{
			tunnelConn: tunnelConn,
			remoteAddr: dst,
			fakeAddr:   dst, // response packets are injected back with this as src
		}
		session.lastActive.Store(time.Now().UnixNano())

		actual, loaded := h.udpSessions.LoadOrStore(key, session)
		if loaded {
			tunnelConn.Close()
			session = actual.(*udpSession)
		} else {
			log.V("[TUN UDP] New session: %s -> %s", src, dst)

			if err := tunnelConn.ConnectUDP(endpoint, nil); err != nil {
				log.Printf("[TUN UDP] ConnectUDP failed: %v", err)
				tunnelConn.Close()
				h.udpSessions.Delete(key)
				return
			}

			log.V("[TUN UDP] ConnectUDP success: endpoint=%v", endpoint)
			go h.udpReadLoop(src, key, session)
		}
	} else {
		session = val.(*udpSession)
	}

	session.lastActive.Store(time.Now().UnixNano())

	log.V("[TUN UDP] Before WriteUDP: endpoint=%s payload_len=%d", endpoint, len(payload))
	if err := session.tunnelConn.WriteUDP(endpoint, payload); err != nil {
		log.Warn("[TUN UDP] WriteUDP failed for %s: %v (type: %T)", endpoint, err, err)
		return
	}
	log.V("[TUN UDP] After WriteUDP success")
}

// udpReadLoop continuously reads UDP responses from the proxy tunnel and writes them back to the TUN stack.
func (h *Handler) udpReadLoop(tunClientSrc netip.AddrPort, key udpSessionKey, session *udpSession) {
	defer h.udpSessions.Delete(key)
	defer session.tunnelConn.Close()

	if h.udpWriter != nil && session.remoteAddr.IsValid() {
		defer h.udpWriter.ReleaseConn(session.remoteAddr, tunClientSrc)
	}

	stopPing := session.tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	buf := commpool.GetLarge()
	defer commpool.PutLarge(buf)

	for {
		n, remoteAddr, err := session.tunnelConn.ReadUDPFrom(buf)
		if err != nil {
			log.V("[TUN UDP] Session read loop closed for %s->%s: %v", tunClientSrc, key.dst, err)
			return
		}
		log.V("[TUN UDP] Read response: remoteAddr=%s payloadLen=%d", remoteAddr, n)

		if h.udpWriter == nil || h.ctx.Err() != nil {
			return
		}

		// Determine the source address to inject into TUN.
		//
		// The server returns the real remote address in each response frame (remoteAddr).
		// We must inject the response with a source IP that the client's gVisor socket
		// will accept. In FakeIP mode the client sent to a FakeIP, so we must respond
		// from that same FakeIP — not from the real server IP.
		//
		// Strategy:
		//   1. Use remoteAddr to reverse-lookup the FakeIP pool. If the server echoes
		//      back the real destination IP and we have a FakeIP for it, use that FakeIP.
		//   2. Fall back to session.fakeAddr (the FakeIP the client originally sent to).
		//      This is always correct for single-destination sessions.
		injectSrc := session.fakeAddr
		if h.fakeIPPool != nil && remoteAddr.IsValid() {
			unmapped := remoteAddr.Addr().Unmap()
			if domain, ok := h.fakeIPPool.LookupByIP(unmapped); ok {
				// remoteAddr itself is a FakeIP — use it directly
				injectSrc = remoteAddr
				_ = domain
			}
			// remoteAddr is a real IP; the correct FakeIP to respond from is the
			// one the client originally sent to (session.fakeAddr = key.dst), which
			// is already set above.
		}

		if !injectSrc.IsValid() {
			injectSrc = remoteAddr
		}

		if injectSrc.IsValid() {
			if err := h.udpWriter.InjectUDP(buf[:n], injectSrc, tunClientSrc); err != nil {
				log.V("[TUN UDP] Inject to TUN failed: %v", err)
			}
		} else {
			log.V("[TUN UDP] Dropping reply: no valid source address for session %s->%s", tunClientSrc, key.dst)
		}
	}
}

func (h *Handler) cleanupUDPSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Minute).UnixNano()
			h.udpSessions.Range(func(key, value interface{}) bool {
				session := value.(*udpSession)
				if session.lastActive.Load() < cutoff {
					log.V("[TUN UDP] Cleaning up inactive NAT session: %s", key)
					session.tunnelConn.Close()
					h.udpSessions.Delete(key)
				}
				return true
			})
		}
	}
}



// handleDNSFakeIP intercepts a DNS query and returns a fake IP instantly.
// No tunnel connection is needed — pure memory operation, < 1ms response.
func (h *Handler) handleDNSFakeIP(query []byte, src netip.AddrPort, dst netip.AddrPort) {
	if len(query) < 12 {
		return
	}

	// Extract the queried domain name
	domain := dns.ParseDNSName(query)
	if domain == "" {
		log.V("[TUN DNS] FakeIP: unable to parse domain from query")
		return
	}

	// Allocate fake IPs for this domain
	fakeIPv4 := h.fakeIPPool.AllocateIPv4(domain)
	fakeIPv6 := h.fakeIPPool.AllocateIPv6(domain)

	// Build DNS response with the fake IP
	response := dns.BuildDNSResponse(query, fakeIPv4, fakeIPv6)
	if response == nil {
		log.V("[TUN DNS] FakeIP: unsupported query for %s", domain)
		return
	}

	// Inject response directly into TUN (bypasses gVisor transport to avoid port conflict)
	if h.udpWriter != nil && h.ctx.Err() == nil {
		if err := h.udpWriter.InjectUDP(response, dst, src); err != nil {
			log.Printf("[TUN DNS] FakeIP: inject response failed: %v", err)
		} else {
			log.Printf("[TUN DNS] FakeIP: %s -> %s", domain, fakeIPv4)
		}
	}
}
