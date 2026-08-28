package netfw

import (
	"fmt"
	"net/netip"
	"strings"
)

// MasterV6Table is the nft table holding the master's client-facing IPv6 policy.
// Separate from the NAT table because it lives in a different address family and
// nftables will not mix them.
const MasterV6Table = "wgfleet_master_v6"

// RenderMasterV6Block renders the IPv6 half of the client-facing policy: refuse
// forwarded IPv6 AUDIBLY.
//
// The data plane is IPv4-only, so a client handed "::/0" has nowhere to go — and
// how it is told matters more than that it is told. Dropped silently, the client's
// OS waits out a connect timeout on every dual-stack destination happy eyeballs
// prefers, which looks exactly like a flaky link or an MTU problem and reads that
// way for days. Rejected with ICMPv6 administratively-prohibited, it falls back to
// IPv4 in milliseconds and the user notices nothing. The route is not the hazard;
// the route without the answer is.
//
// The chain's policy is drop and only the client prefix is rejected. Turning on
// IPv6 forwarding is what lets the kernel reach a forward chain at all — without it
// the packet is discarded before any rule runs and no ICMP is generated — but a
// master with a public IPv6 address must not become an open router in the process.
// So forwarding is enabled and then everything except the one thing we mean to
// answer is dropped outright.
func RenderMasterV6Block(clientIface, ipv6Prefix string) (string, error) {
	if clientIface == "" {
		return "", fmt.Errorf("netfw master v6: client interface is required")
	}
	p, err := netip.ParsePrefix(ipv6Prefix)
	if err != nil {
		return "", fmt.Errorf("netfw master v6: invalid prefix %q: %w", ipv6Prefix, err)
	}
	if !p.Addr().Is6() {
		return "", fmt.Errorf("netfw master v6: %q is not an IPv6 prefix", ipv6Prefix)
	}
	// Re-emit from the parsed form so no manifest-derived string can inject syntax
	// into a root-applied ruleset.
	prefix := p.Masked().String()

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Rendered by wgfleet — master client-facing IPv6 (refuse, audibly). Do not edit by hand.\n")
	// Same atomic replace idiom as the NAT table: without it a re-apply appends to
	// the existing chains and stale rules accumulate forever.
	fmt.Fprintf(&b, "table ip6 %s\n", MasterV6Table)
	fmt.Fprintf(&b, "delete table ip6 %s\n", MasterV6Table)
	fmt.Fprintf(&b, "table ip6 %s {\n", MasterV6Table)
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy drop;\n")
	// ICMPv6 is not optional plumbing in IPv6 the way ICMP is in IPv4: neighbour
	// discovery and path MTU ride on it, so blanket-dropping it breaks the link
	// itself rather than just the routing.
	b.WriteString("\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, packet-too-big } accept\n")
	fmt.Fprintf(&b, "\t\tiifname %q ip6 saddr %s counter reject with icmpv6 type admin-prohibited\n", clientIface, prefix)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}
