package ewpclient

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"ewp-core/engine"
	v2 "ewp-core/protocol/ewp/v2"
)

// ProbeResult is the outcome of one ProbeNAT call.
type ProbeResult struct {
	// Target is the dst the probe was sent toward (e.g. a STUN
	// server). It is the address the client believes it's
	// dialling — useful for cross-checking.
	Target engine.Endpoint
	// Reflexive is what the EWP server reports as the
	// publicly-observable mapping (IP:Port).
	Reflexive netip.AddrPort
	// ReflexiveIsDomain is true when the server only knows a
	// hostname for itself (rare).
	ReflexiveDomain string
}

// ProbeNAT exchanges one UDP_PROBE_REQ / UDP_PROBE_RESP via a fresh
// sub-session and reports the reflexive address the EWP server saw
// after STUN-discovering its own public mapping.
//
// Designed to be called from a CLI ("ewp -probe-nat") or from a
// long-running diagnostics goroutine. Does NOT spawn a sub-session
// for ongoing UDP traffic — Probe is one-shot.
func (o *Outbound) ProbeNAT(ctx context.Context, target engine.Endpoint) (ProbeResult, error) {
	if o.isClosed() {
		return ProbeResult{}, errors.New("ewpclient: closed")
	}

	// Synthesise a per-probe src so the tunnel map keys cleanly.
	probeSrc := engine.Endpoint{
		Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(0)),
	}
	addr, err := endpointToAddress(target)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("ewpclient: target: %w", err)
	}
	tun, err := o.tunnelForSrc(ctx, probeSrc, addr)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("ewpclient: dial tunnel: %w", err)
	}

	gid := v2.NewGlobalID()
	sub := tun.openSub(gid, addr)
	defer tun.removeSub(gid)

	probedAddr, err := sub.Probe()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("ewpclient: probe: %w", err)
	}
	res := ProbeResult{Target: target}
	if probedAddr.Domain != "" {
		res.ReflexiveDomain = probedAddr.Domain
	} else {
		res.Reflexive = probedAddr.Addr
	}
	return res, nil
}
