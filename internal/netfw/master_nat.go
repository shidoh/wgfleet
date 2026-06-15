package netfw

import (
	"fmt"
	"strings"
)

// MasterNATTable is the nft table name the master NAT ruleset lives in. Exported
// so the agent can probe the live kernel for it (live-kernel reload gate) with
// the exact same name the renderer emits.
const MasterNATTable = "wgfleet_master"

// MasterNATInput is the context for rendering the master's NAT/mangle ruleset.
// On the master, client traffic arriving on the client WG interface is DNAT'd to
// mihomo's redir-port, masqueraded outbound, and QUIC (UDP/443) is dropped so
// browsers fall back to TCP paths the router can handle (the reference deployment §3.11, an earlier finding context).
type MasterNATInput struct {
	ClientInterface string // client WG interface, e.g. "wg0"
	ClientCIDR      string // client WG pool, e.g. "10.80.0.0/24"
	RedirAddr       string // mihomo redir target, e.g. "10.80.0.1:7895"
	EgressInterface string // public uplink for MASQUERADE, e.g. "ens3"
	// PrivateCIDRs are destinations that bypass the DNAT (kept DIRECT): RFC1918,
	// CGNAT, mgmt overlay. Rendered as `ip daddr != <cidr>` guards.
	PrivateCIDRs []string
}

// RenderMasterNAT renders the master's nft NAT ruleset: drop client QUIC, DNAT
// non-private client TCP to mihomo, and MASQUERADE client traffic outbound.
func RenderMasterNAT(in MasterNATInput) (string, error) {
	if in.ClientInterface == "" || in.ClientCIDR == "" || in.RedirAddr == "" {
		return "", fmt.Errorf("netfw master NAT: client interface, CIDR and redir addr are required")
	}
	if in.EgressInterface == "" {
		return "", fmt.Errorf("netfw master NAT: egress interface is required for MASQUERADE")
	}

	guards := privateGuards(in.PrivateCIDRs)

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Rendered by wgfleet — master NAT (mihomo DNAT + MASQUERADE). Do not edit by hand.\n")
	fmt.Fprintf(&b, "table ip %s {\n", MasterNATTable)

	b.WriteString("\tchain prerouting {\n")
	b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	// Drop client QUIC so browsers fall back to TCP through mihomo.
	fmt.Fprintf(&b, "\t\tiifname %q%s udp dport 443 drop\n", in.ClientInterface, guards)
	// DNAT non-private client TCP to mihomo's redir-port.
	fmt.Fprintf(&b, "\t\tiifname %q%s ip protocol tcp dnat to %s\n", in.ClientInterface, guards, in.RedirAddr)
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "\t\tip saddr %s oifname %q masquerade\n", in.ClientCIDR, in.EgressInterface)
	b.WriteString("\t}\n")

	b.WriteString("}\n")
	return b.String(), nil
}

// privateGuards renders the `ip daddr != <cidr>` guard chain that keeps private
// destinations out of the DNAT/drop rules.
func privateGuards(cidrs []string) string {
	var b strings.Builder
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		fmt.Fprintf(&b, " ip daddr != %s", c)
	}
	return b.String()
}
