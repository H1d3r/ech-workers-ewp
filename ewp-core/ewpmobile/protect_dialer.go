package ewpmobile

import (
	"net"
	"syscall"

	"ewp-core/transport"
)

func makeProtectedBypassConfig() *transport.BypassConfig {
	return makeProtectedBypassConfigWithDoH(nil)
}

func makeProtectedBypassConfigWithDoH(dohServers []string) *transport.BypassConfig {
	// P1-17: ProtectSocket failure must propagate as error to prevent routing loops.
	// If protect fails, the socket will route back into the TUN device, causing
	// infinite recursion, OOM, and battery drain.
	control := func(network, address string, c syscall.RawConn) error {
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
	cfg := &transport.BypassConfig{
		TCPDialer:       &net.Dialer{Control: control},
		UDPListenConfig: &net.ListenConfig{Control: control},
	}
	
	// Use custom DoH servers if provided (from ech.doh_servers)
	var dohServer string
	if len(dohServers) == 1 {
		dohServer = dohServers[0]
	}
	cfg.Resolver = transport.NewBypassResolver(cfg, dohServer, dohServers)
	return cfg
}
