package net

import (
	"context"
	"net"
	"syscall"
	"time"

	"ewp-core/log"
)

// P2-38: TCP Fast Open Implementation Notes
//
// IMPORTANT: Current implementation only sets TCP_FASTOPEN socket option,
// but does NOT send data in the initial SYN packet (true TFO).
//
// What this implementation does:
// - Sets TCP_FASTOPEN socket option on client and server sockets
// - Allows the kernel to use TFO if both sides support it
// - Uses standard Dial/DialContext which performs normal 3-way handshake
//
// What this implementation does NOT do:
// - Does NOT send application data in the SYN packet (sendto + MSG_FASTOPEN)
// - Does NOT reduce connection establishment latency in the first round trip
//
// Why not full TFO implementation:
// 1. Requires low-level socket programming (sendto with MSG_FASTOPEN)
// 2. May not work behind certain NAT/firewalls
// 3. Requires buffering first write data before connection establishment
// 4. Complex error handling and fallback logic
//
// For true TFO implementation, consider using:
// - github.com/getlantern/go-tfo library
// - Custom implementation with syscall.Sendto + MSG_FASTOPEN
//
// Current implementation provides:
// - Socket-level TFO enablement (kernel may use TFO for subsequent connections)
// - Graceful fallback to standard TCP if TFO is not supported
// - No breaking changes to existing connection logic

// DialTFO establishes a TCP connection with TCP Fast Open socket option enabled
// Note: This does NOT send data in SYN packet. See package documentation for details.
func DialTFO(network, address string, timeout time.Duration) (net.Conn, error) {
	return DialTFOContext(context.Background(), network, address, timeout)
}

// DialTFOContext establishes a TCP connection with TCP Fast Open socket option enabled
// Note: This does NOT send data in SYN packet. See package documentation for details.
func DialTFOContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	// Parse address
	tcpAddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// Create socket with TFO support
	conn, err := dialTCPWithTFO(ctx, tcpAddr, timeout)
	if err != nil {
		// Fallback to standard dial if TFO fails
		log.V("[TFO] Failed to enable TCP Fast Open socket option, falling back to standard dial: %v", err)

		if timeout > 0 {
			return net.DialTimeout(network, address, timeout)
		}

		d := &net.Dialer{}
		return d.DialContext(ctx, network, address)
	}

	return conn, nil
}

// dialTCPWithTFO creates a TCP connection with Fast Open socket option enabled
func dialTCPWithTFO(ctx context.Context, addr *net.TCPAddr, timeout time.Duration) (net.Conn, error) {
	// Create dialer with TFO-specific configuration
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var syscallErr error
			err := c.Control(func(fd uintptr) {
				// Enable TCP Fast Open on the socket
				syscallErr = enableTFO(int(fd))
			})
			if err != nil {
				return err
			}
			return syscallErr
		},
	}

	return d.DialContext(ctx, "tcp", addr.String())
}

// ListenTFO creates a TCP listener with TCP Fast Open enabled
func ListenTFO(network, address string) (net.Listener, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var syscallErr error
			err := c.Control(func(fd uintptr) {
				// Enable TCP Fast Open on the listener socket
				syscallErr = enableTFOListener(int(fd))
			})
			if err != nil {
				return err
			}
			return syscallErr
		},
	}

	lis, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		// Fallback to standard listen if TFO fails
		log.V("[TFO] Failed to enable TCP Fast Open on listener, falling back to standard listen: %v", err)
		return net.Listen(network, address)
	}

	return lis, nil
}
