package ewpserver

import "net/netip"

// addrPortFromBytes4 / addrPortFromBytes16 are tiny helpers used by
// SetReflexive to avoid pulling netip into the Inbound API surface.
func addrPortFromBytes4(ip [4]byte, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(ip), port)
}

func addrPortFromBytes16(ip [16]byte, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16(ip), port)
}
