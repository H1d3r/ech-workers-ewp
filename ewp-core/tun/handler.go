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

// udpResponseWriter is the write-side of a gVisor UDP socket.
// Using an interface allows tests to substitute a mock without importing gVisor.
type udpResponseWriter interface {
	Write(b []byte) (int, error)
	Close() error
}

// udpSession represents a proxy tunnel connection for a specific (src, dst) UDP flow.
type udpSession struct {
	tunnelConn transport.TunnelConn
	gvisorConn udpResponseWriter // gVisor socket for this flow — write responses directly here
	remoteAddr netip.AddrPort    // the remote server addr (responses appear to come FROM here)
	fakeAddr   netip.AddrPort    // FakeIP:Port the client sent to — injected back as response src
	lastActive atomic.Int64      // UnixNano; updated on every packet, read by cleanup goroutine
}

type Handler struct {
	transport  transport.Transport
	ctx        context.Context
	fakeIPPool *dns.FakeIPPool

	udpSessions sync.Map // map[udpSessionKey]*udpSession
}

func NewHandler(ctx context.Context, trans transport.Transport) *Handler {
	h := &Handler{
		transport: trans,
		ctx:       ctx,
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

// HandleUDP is called by the gVisor UDP forwarder for every incoming UDP packet.
// conn is the gVisor socket for this (src,dst) flow; writing to it delivers data
// back to the TUN client without any port-conflict issues.
func (h *Handler) HandleUDP(conn udpResponseWriter, payload []byte, src netip.AddrPort, dst netip.AddrPort) {
	log.V("[TUN UDP] HandleUDP: src=%s dst=%s payload_len=%d", src, dst, len(payload))

	// DNS interception: use FakeIP for instant response
	if dst.Port() == 53 && h.fakeIPPool != nil {
		h.handleDNSFakeIP(conn, payload, src, dst)
		return
	}

	// Reverse-lookup fake IP to domain for UDP endpoint.
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
		if conn == nil {
			// No existing session and no conn — packet arrived out of order, drop.
			return
		}
		tunnelConn, err := h.transport.Dial()
		if err != nil {
			log.Printf("[TUN UDP] Tunnel dial failed for %s->%s: %v", src, dst, err)
			conn.Close()
			return
		}

		session = &udpSession{
			tunnelConn: tunnelConn,
			gvisorConn: conn,
			remoteAddr: dst,
			fakeAddr:   dst,
		}
		session.lastActive.Store(time.Now().UnixNano())

		actual, loaded := h.udpSessions.LoadOrStore(key, session)
		if loaded {
			// Another goroutine beat us; close what we just made and use existing.
			tunnelConn.Close()
			conn.Close()
			session = actual.(*udpSession)
		} else {
			log.V("[TUN UDP] New session: %s -> %s", src, dst)

			if err := tunnelConn.ConnectUDP(endpoint, nil); err != nil {
				log.Printf("[TUN UDP] ConnectUDP failed: %v", err)
				tunnelConn.Close()
				conn.Close()
				h.udpSessions.Delete(key)
				return
			}

			log.V("[TUN UDP] ConnectUDP success: endpoint=%v", endpoint)
			go h.udpReadLoop(src, key, session)
		}
	} else {
		session = val.(*udpSession)
		// conn from gVisor for an existing session — gVisor created a new endpoint
		// for a new packet on the same (src,dst). Close it; we already have one.
		if conn != nil {
			conn.Close()
		}
	}

	session.lastActive.Store(time.Now().UnixNano())

	log.V("[TUN UDP] Before WriteUDP: endpoint=%s payload_len=%d", endpoint, len(payload))
	if err := session.tunnelConn.WriteUDP(endpoint, payload); err != nil {
		log.Warn("[TUN UDP] WriteUDP failed for %s: %v (type: %T)", endpoint, err, err)
		return
	}
	log.V("[TUN UDP] After WriteUDP success")
}

// udpReadLoop continuously reads UDP responses from the proxy tunnel and writes them back
// to the TUN client via session.gvisorConn — the gonet.UDPConn gVisor created for this flow.
// Writing directly to the gVisor conn avoids the port-conflict problem that arises when
// trying to DialUDP on an already-bound (src,dst) pair, and avoids the raw-packet injection
// path that gVisor silently drops when no matching socket exists.
func (h *Handler) udpReadLoop(tunClientSrc netip.AddrPort, key udpSessionKey, session *udpSession) {
	defer h.udpSessions.Delete(key)
	defer session.tunnelConn.Close()
	defer session.gvisorConn.Close()

	stopPing := session.tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	buf := commpool.GetLarge()
	defer commpool.PutLarge(buf)

	for {
		n, _, err := session.tunnelConn.ReadUDPFrom(buf)
		if err != nil {
			log.V("[TUN UDP] Session read loop closed for %s->%s: %v", tunClientSrc, key.dst, err)
			return
		}

		if h.ctx.Err() != nil {
			return
		}

		// Write the response payload directly to the gVisor conn.
		// gVisor delivers it to the client socket that originally sent the packet,
		// with the correct source address (the dst the client sent to) automatically.
		if _, err := session.gvisorConn.Write(buf[:n]); err != nil {
			log.V("[TUN UDP] Write to gVisor conn failed for %s->%s: %v", tunClientSrc, key.dst, err)
			return
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
// conn is the gVisor socket for this DNS flow; we write the response directly
// to it and then close it.
func (h *Handler) handleDNSFakeIP(conn udpResponseWriter, query []byte, src netip.AddrPort, dst netip.AddrPort) {
	if conn != nil {
		defer conn.Close()
	}
	if len(query) < 12 {
		return
	}

	domain := dns.ParseDNSName(query)
	if domain == "" {
		log.V("[TUN DNS] FakeIP: unable to parse domain from query")
		return
	}

	fakeIPv4 := h.fakeIPPool.AllocateIPv4(domain)
	fakeIPv6 := h.fakeIPPool.AllocateIPv6(domain)

	response := dns.BuildDNSResponse(query, fakeIPv4, fakeIPv6)
	if response == nil {
		log.V("[TUN DNS] FakeIP: unsupported query for %s", domain)
		return
	}

	if conn != nil && h.ctx.Err() == nil {
		if _, err := conn.Write(response); err != nil {
			log.Printf("[TUN DNS] FakeIP: write response failed: %v", err)
		} else {
			log.Printf("[TUN DNS] FakeIP: %s -> %s", domain, fakeIPv4)
		}
	}
}
