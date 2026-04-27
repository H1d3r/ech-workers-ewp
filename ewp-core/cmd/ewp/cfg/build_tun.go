//go:build !android

package cfg

import (
	"errors"
	"fmt"

	"ewp-core/engine"
	"ewp-core/tun"
)

// buildTUNInbound builds a TUN inbound from yaml. Only available on
// non-android builds; mobile bindings construct their own TUN via
// the OS-supplied file descriptor in package ewpmobile.
func buildTUNInbound(c InboundCfg) (engine.Inbound, error) {
	if c.TUN.Address == "" {
		return nil, errors.New("tun inbound: tun.address (e.g. 198.18.0.1/24) is required")
	}
	dnsv4 := ""
	dnsv6 := ""
	if len(c.TUN.DNS) > 0 {
		dnsv4 = c.TUN.DNS[0]
	}
	if len(c.TUN.DNS) > 1 {
		dnsv6 = c.TUN.DNS[1]
	}
	mtu := c.TUN.MTU
	if mtu <= 0 {
		mtu = 1500
	}

	t, err := tun.New(&tun.Config{
		IP:         c.TUN.Address,
		DNS:        dnsv4,
		IPv6DNS:    dnsv6,
		MTU:        mtu,
		Stack:      "gvisor",
		ServerAddr: c.TUN.BypassServer,
	})
	if err != nil {
		return nil, fmt.Errorf("tun inbound: %w", err)
	}
	if err := t.Setup(); err != nil {
		return nil, fmt.Errorf("tun setup: %w", err)
	}
	return t.AsInbound(c.Tag), nil
}
