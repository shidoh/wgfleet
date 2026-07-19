package keybroker

import (
	"fmt"
	"net/netip"
)

// Tunnel addressing convention for a master↔exit link inside the exit's pool:
// the exit (server) takes host .1, the master (client) takes host .2. Keeping
// this deterministic means the controller can render both ends without an IPAM.
const (
	exitHostIndex   = 1
	masterHostIndex = 2
	// masterPerTunnelHostIndex is the master's address when it dials with its
	// PER-TUNNEL identity (ADR-0030). It must differ from masterHostIndex: WireGuard
	// AllowedIPs is a routing trie, so the legacy peer and the per-tunnel peer cannot
	// both claim host .2 — the second one configured would silently steal the /32 and
	// the first would lose its return path. A distinct host makes the two peers
	// coexist during the migration's `dual`/`switch` phases.
	masterPerTunnelHostIndex = 3
)

// nthHost returns the nth usable host address in cidr (1-based; n=1 is the
// first host after the network address). It returns a host-only string such as
// "10.81.0.1" suitable for an interface address, and "10.81.0.1/32" via host32.
func nthHost(cidr string, n int) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	addr := prefix.Masked().Addr()
	for i := 0; i < n; i++ {
		addr = addr.Next()
		if !addr.IsValid() || !prefix.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("cidr %q too small for host index %d", cidr, n)
		}
	}
	return addr, nil
}

// host32 renders addr as a single-host CIDR ("/32" for IPv4, "/128" for IPv6),
// the AllowedIPs form used for point-to-point tunnel peers.
func host32(addr netip.Addr) string {
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return fmt.Sprintf("%s/%d", addr.String(), bits)
}
