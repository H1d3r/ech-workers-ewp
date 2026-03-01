//go:build darwin

package setup

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func SetupTUN(ifName, ipCIDR, ipv6CIDR, dns, ipv6DNS string, mtu int) error {
	if ipCIDR != "" {
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/24"
		}
		prefix, err := netip.ParsePrefix(ipCIDR)
		if err != nil {
			return fmt.Errorf("parse IPv4 CIDR: %w", err)
		}
		local := prefix.Addr().Unmap()
		peer := peerAddr(local)

		// macOS utun is a point-to-point interface: ifconfig <iface> <local> <peer>
		if err := run("ifconfig", ifName, local.String(), peer.String(), "mtu", fmt.Sprint(mtu), "up"); err != nil {
			return fmt.Errorf("ifconfig IPv4: %w", err)
		}
		if err := run("route", "add", "-net", "0.0.0.0/0", peer.String()); err != nil {
			return fmt.Errorf("add IPv4 default route: %w", err)
		}
	}

	if ipv6CIDR != "" {
		if !strings.Contains(ipv6CIDR, "/") {
			ipv6CIDR += "/64"
		}
		prefix, err := netip.ParsePrefix(ipv6CIDR)
		if err != nil {
			return fmt.Errorf("parse IPv6 CIDR: %w", err)
		}
		local := prefix.Addr()
		if err := run("ifconfig", ifName, "inet6", local.String(),
			"prefixlen", fmt.Sprint(prefix.Bits()), "up"); err != nil {
			return fmt.Errorf("ifconfig IPv6: %w", err)
		}
		if err := run("route", "add", "-inet6", "default", "-interface", ifName); err != nil {
			return fmt.Errorf("add IPv6 default route: %w", err)
		}
	}

	// Override the global DNS resolver via the System Configuration dynamic store.
	// Setting State:/Network/Global/DNS tells mDNSResponder to use these servers
	// for all queries, replacing any per-interface DNS that might point to the
	// LAN gateway (which would bypass TUN via a more-specific subnet route).
	// The key is removed in TeardownTUN to restore original resolver settings.
	if dns != "" || ipv6DNS != "" {
		_ = setMacOSDNS(dns, ipv6DNS)
	}

	return nil
}

func TeardownTUN(ifName string) error {
	_ = run("route", "delete", "-net", "default", "-interface", ifName)
	_ = run("route", "delete", "-inet6", "default", "-interface", ifName)
	_ = run("ifconfig", ifName, "down")
	_ = clearMacOSDNS()
	return nil
}

// setMacOSDNS overrides the global DNS via scutil (System Configuration store).
// scutil array syntax: "d.add Key * val1 val2 ..."  (the * signals CFArray type)
func setMacOSDNS(dns, ipv6DNS string) error {
	line := "d.add ServerAddresses *"
	if dns != "" {
		line += " " + dns
	}
	if ipv6DNS != "" {
		line += " " + ipv6DNS
	}

	script := "d.init\n" + line + "\nset State:/Network/Global/DNS\n"
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("scutil set DNS: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// clearMacOSDNS removes the override set by setMacOSDNS, restoring normal DNS.
func clearMacOSDNS() error {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader("remove State:/Network/Global/DNS\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil remove DNS: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// peerAddr returns the "remote" end of the point-to-point link: local ± 1 on the last byte.
func peerAddr(local netip.Addr) netip.Addr {
	if local.Is4() {
		a := local.As4()
		if a[3] < 255 {
			a[3]++
		} else {
			a[3]--
		}
		return netip.AddrFrom4(a)
	}
	a := local.As16()
	if a[15] < 255 {
		a[15]++
	} else {
		a[15]--
	}
	return netip.AddrFrom16(a)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
