package tun

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"ewp-core/dns"
	"ewp-core/log"
	ewpgvisor "ewp-core/tun/gvisor"
)

// NewWithFD constructs a TUN bound to a file descriptor handed in by
// the operating system (notably Android's VpnService.establish()).
//
// Unlike New(), this does NOT call tun.CreateTUN — the caller already
// owns the TUN device and is responsible for closing the underlying
// fd if the returned error is non-nil. On success, ownership of the
// fd transfers to the returned *TUN; calling Close() on it will both
// shut down the gVisor stack and close the fd via the wgtun.Device
// wrapper.
//
// The fd MUST be a TUN/TAP file descriptor in non-blocking mode (the
// VpnService API satisfies this).
func NewWithFD(cfg *Config, tunFD int) (*TUN, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	ctx, cancel := context.WithCancel(context.Background())

	handler := NewHandler(ctx)

	pool := dns.NewFakeIPPool()
	handler.SetFakeIPPool(pool)

	mtu := uint32(cfg.MTU)
	if mtu == 0 {
		mtu = 1420 // typical Android default
	}

	if cfg.IP != "" {
		ipStr := cfg.IP
		if !strings.Contains(ipStr, "/") {
			ipStr += "/24"
		}
		if _, err := netip.ParsePrefix(ipStr); err != nil {
			cancel()
			return nil, fmt.Errorf("parse IPv4: %w", err)
		}
	}

	// Wrap the os.File around the fd. wgtun.CreateTUNFromFile takes
	// ownership and will Close() it when the device is closed.
	f := os.NewFile(uintptr(tunFD), "tun")
	if f == nil {
		cancel()
		return nil, fmt.Errorf("invalid tunFD %d", tunFD)
	}
	dev, err := wgtun.CreateTUNFromFile(f, int(mtu))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("CreateTUNFromFile: %w", err)
	}

	stack, err := ewpgvisor.NewStack(dev, &ewpgvisor.StackConfig{
		MTU:        int(mtu),
		TCPHandler: handler.HandleTCP,
		UDPHandler: func(conn *gonet.UDPConn, payload []byte, src netip.AddrPort, dst netip.AddrPort) {
			handler.HandleUDP(conn, payload, src, dst)
		},
	})
	if err != nil {
		dev.Close()
		cancel()
		return nil, fmt.Errorf("gvisor stack: %w", err)
	}

	log.Printf("[TUN] attached to fd=%d mtu=%d", tunFD, mtu)
	return &TUN{
		device:    dev,
		stack:     stack,
		handler:   handler,
		fakePool:  pool,
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		closeOnce: sync.Once{},
	}, nil
}
