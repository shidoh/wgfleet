// Package wg holds WireGuard/AmneziaWG helpers shared across the codebase. The
// config rendering and wgctrl wrappers land here in later milestones; for now it
// provides the MTU primitives that encode docs/DESIGN.md an earlier finding ("MTU is computed,
// not guessed").
package wg

// MTU overhead constants. Each WireGuard layer subtracts a fixed header cost;
// nesting tunnels stacks these, which is exactly the trap an earlier finding warns about.
const (
	// DefaultPhysicalMTU is the assumed underlying link MTU when none is probed.
	DefaultPhysicalMTU = 1500

	// WGOverheadIPv4 is the per-packet overhead of a plain WireGuard tunnel over
	// IPv4 (20 IP + 8 UDP + 32 WG ≈ 60).
	WGOverheadIPv4 = 60
	// WGOverheadIPv6 is the equivalent over IPv6 (40 IP + 8 UDP + 32 WG ≈ 80).
	WGOverheadIPv6 = 80

	// AWGExtraOverhead is the *additional* headroom reserved for AmneziaWG
	// obfuscation on top of the plain WG overhead. an earlier finding notes AWG adds
	// ">60"; we reserve conservatively so junk/decoy packets never fragment.
	AWGExtraOverhead = 80

	// MinTunnelMTU is the IPv6 minimum; below this, tunnels are unreliable.
	MinTunnelMTU = 1280
)

// TunnelMTU returns the MTU available *inside* one tunnel layer carried over an
// outer link of outerMTU. Set awg when the layer is AmneziaWG-obfuscated and
// ipv6 when the outer transport is IPv6.
func TunnelMTU(outerMTU int, awg, ipv6 bool) int {
	overhead := WGOverheadIPv4
	if ipv6 {
		overhead = WGOverheadIPv6
	}
	if awg {
		overhead += AWGExtraOverhead
	}
	return outerMTU - overhead
}

// FleetTunnelMTU returns the MTU for a single wgfleet WireGuard hop.
//
// The wgfleet data plane is a chain of *terminating* hops, not a nested stack:
// client→master(AWG), master→exit(AWG) and exit→WARP(WG) each decrypt the carried
// packet down to the bare client payload and re-encapsulate it afresh over their
// own physical link (sequential model, ADR-0014). Because no hop rides inside
// another, every hop's MTU is independent — the physical link minus that one
// layer's overhead — rather than an accumulating subtraction down the chain.
//
// The binding client-interface MTU is therefore the minimum across the hops the
// client payload traverses (use MinMTU); each hop on its own gets the value this
// returns. Set awg for AmneziaWG-obfuscated hops and ipv6 for IPv6 transport.
func FleetTunnelMTU(awg, ipv6 bool) int {
	return TunnelMTU(DefaultPhysicalMTU, awg, ipv6)
}

// MinMTU returns the smallest of the given hop MTUs, i.e. the largest payload
// that survives every hop without fragmenting. The client interface must be set
// to this so a full-size client packet never fragments at a downstream hop
// (an earlier finding: the "first N requests fail" / "message too long" trap).
func MinMTU(mtus ...int) int {
	if len(mtus) == 0 {
		return 0
	}
	smallest := mtus[0]
	for _, m := range mtus[1:] {
		if m < smallest {
			smallest = m
		}
	}
	return smallest
}
