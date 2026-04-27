package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"ewp-core/cmd/ewp/cfg"
	"ewp-core/engine"
	"ewp-core/outbound/ewpclient"
)

// runProbeAndExit performs a single UDP_PROBE_REQ via the default
// ewpclient outbound and prints what the EWP server believes our
// public mapping is.
//
// Exit codes:
//
//	0 — probe succeeded, result printed
//	1 — probe failed (config wrong, server unreachable, etc.)
//	2 — config has no ewpclient outbound to probe through
func runProbeAndExit(ctx context.Context, eng *engine.Engine, conf *cfg.File, target string) {
	dst, err := parseProbeTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe-nat: bad target %q: %v\n", target, err)
		os.Exit(1)
	}

	defaultTag := conf.Router.Default
	out := eng.OutboundByTag(defaultTag)
	if out == nil {
		fmt.Fprintf(os.Stderr, "probe-nat: default outbound %q not found\n", defaultTag)
		os.Exit(2)
	}
	cli, ok := out.(*ewpclient.Outbound)
	if !ok {
		fmt.Fprintf(os.Stderr, "probe-nat: default outbound %q is not an ewpclient (type=%T); probe-nat only works against EWP server\n", defaultTag, out)
		os.Exit(2)
	}

	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	res, err := cli.ProbeNAT(pctx, dst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe-nat: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Target sent through:   %s\n", endpointString(res.Target))
	switch {
	case res.Reflexive.IsValid():
		fmt.Printf("Server-observed addr:  %s\n", res.Reflexive)
	case res.ReflexiveDomain != "":
		fmt.Printf("Server-observed addr:  %s (domain)\n", res.ReflexiveDomain)
	default:
		fmt.Printf("Server-observed addr:  <unavailable; server has no STUN reflexive yet>\n")
	}
	fmt.Println()
	fmt.Println("Compare the server-observed address with what your local OS")
	fmt.Println("thinks is your public IP. If they match, you're behind a")
	fmt.Println("Full-Cone NAT (or no NAT). If they differ but stay constant")
	fmt.Println("across multiple probes, you're behind a Restricted-Cone NAT.")
	fmt.Println("If the port changes per destination, you're behind a")
	fmt.Println("Symmetric NAT — STUN-style hole-punching will not work.")
}

func parseProbeTarget(s string) (engine.Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return engine.Endpoint{}, err
	}
	pn, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return engine.Endpoint{}, fmt.Errorf("port: %w", err)
	}
	port := uint16(pn)
	if ip, err := netip.ParseAddr(host); err == nil {
		return engine.Endpoint{Addr: netip.AddrPortFrom(ip, port), Port: port}, nil
	}
	return engine.Endpoint{Domain: host, Port: port}, nil
}

func endpointString(e engine.Endpoint) string {
	if e.IsDomain() {
		return fmt.Sprintf("%s:%d", e.Domain, e.Port)
	}
	return e.Addr.String()
}
