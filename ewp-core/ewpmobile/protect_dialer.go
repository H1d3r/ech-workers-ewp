//go:build android

package ewpmobile

import (
	"net"
	"syscall"

	"ewp-core/transport"
)

// wrapBypassWithProtector returns a copy of in with its TCPDialer.Control
// and UDPListenConfig.Control wrapped to invoke VpnService.protect(fd)
// on every fresh socket. The original Control hook (set by tun.Setup
// to bind to the physical interface) is still invoked first.
//
// On Android the bypass dialer alone is not enough: even with the
// right outbound interface chosen, the fd still has to be marked as
// "do not route through this VpnService" or the kernel hands us back
// our own TUN. That's exactly what SocketProtector exposes.
func wrapBypassWithProtector(in *transport.BypassConfig) *transport.BypassConfig {
	if in == nil {
		return nil
	}
	out := *in // shallow copy is enough — we replace pointers below

	wrap := func(prev func(string, string, syscall.RawConn) error) func(string, string, syscall.RawConn) error {
		return func(network, address string, c syscall.RawConn) error {
			if prev != nil {
				if err := prev(network, address, c); err != nil {
					return err
				}
			}
			var protectErr error
			if err := c.Control(func(fd uintptr) {
				if !ProtectSocket(int(fd)) {
					protectErr = &transport.ProtectError{
						Network: network,
						Address: address,
						FD:      int(fd),
					}
				}
			}); err != nil {
				return err
			}
			return protectErr
		}
	}

	if in.TCPDialer != nil {
		d := *in.TCPDialer
		d.Control = wrap(in.TCPDialer.Control)
		out.TCPDialer = &d
	} else {
		out.TCPDialer = &net.Dialer{Control: wrap(nil)}
	}

	if in.UDPListenConfig != nil {
		lc := *in.UDPListenConfig
		lc.Control = wrap(in.UDPListenConfig.Control)
		out.UDPListenConfig = &lc
	} else {
		out.UDPListenConfig = &net.ListenConfig{Control: wrap(nil)}
	}

	return &out
}
