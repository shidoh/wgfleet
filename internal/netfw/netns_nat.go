package netfw

import (
	"fmt"
	"strings"
)

// NetnsNATTable is the nft table rendered INSIDE mihomo's network namespace.
// A different name from the host's on purpose: the two rulesets are read side by
// side during an incident, and two tables called the same thing in two namespaces
// is a way to misread both.
const NetnsNATTable = "wgfleet_netns"

// NetnsNATInput is the context for the in-namespace interception.
type NetnsNATInput struct {
	// PeerIface is the veth end inside the namespace — where client traffic
	// arrives after the host routes it in.
	PeerIface string
	// RedirAddr / TProxyAddr are mihomo's listeners, on the namespace's own
	// address.
	RedirAddr  string
	TProxyAddr string
}

// RenderNetnsNAT renders the interception that used to live on the host.
//
// It has to be here rather than there because of one kernel rule: `tproxy` hands
// the packet to a socket looked up in the CURRENT network namespace. mihomo's
// transparent listeners moved, so the rule that feeds them had to move with them
// — that is the reason the migration cannot be split into "move the proxy" and
// "move the rules" as two separately reversible steps.
//
// What the move buys is that mihomo's reply sockets no longer compete with
// whatever the host binds. On the live master the client AmneziaWG interface
// holds 0.0.0.0:443 without SO_REUSEADDR, so every reply socket mihomo opened for
// a client's QUIC flow failed with EADDRINUSE and the datagram was dropped in
// silence for eight days. In here nothing else binds anything.
func RenderNetnsNAT(in NetnsNATInput) (string, error) {
	if in.PeerIface == "" || in.RedirAddr == "" || in.TProxyAddr == "" {
		return "", fmt.Errorf("netfw netns NAT: peer interface, redir and tproxy addresses are required")
	}

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Rendered by wgfleet — client interception inside mihomo's namespace. Do not edit by hand.\n")
	// Same delete-first idiom as every other table we own: `nft -f` appends
	// otherwise, so re-applying would stack duplicate rules on every pass.
	fmt.Fprintf(&b, "table ip %s\n", NetnsNATTable)
	fmt.Fprintf(&b, "delete table ip %s\n", NetnsNATTable)
	fmt.Fprintf(&b, "table ip %s {\n", NetnsNATTable)

	b.WriteString("\tchain prerouting {\n")
	b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q ip protocol tcp dnat to %s\n", in.PeerIface, in.RedirAddr)
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain client_udp_tproxy {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// `tproxy` BEFORE `meta mark set`, and the order is load-bearing exactly as it
	// is on the host: nft_tproxy_eval returns NFT_BREAK when no transparent socket
	// is listening, which ends the rule — so a mark written first would ride on a
	// packet that was never intercepted and send it somewhere it does not belong.
	fmt.Fprintf(&b, "\t\tiifname %q meta l4proto udp tproxy ip to %s meta mark set %#x accept\n",
		in.PeerIface, in.TProxyAddr, TProxyMark)
	// FAIL CLOSED, for the same reason as on the host: an interception that did not
	// happen is a packet that must not travel. Here it matters more, not less —
	// this namespace has a default route to the host, so an unintercepted datagram
	// would leave by the master's own uplink with the client's address on it.
	fmt.Fprintf(&b, "\t\tiifname %q meta l4proto udp counter drop\n", in.PeerIface)
	b.WriteString("\t}\n\n")

	// Client traffic leaves this namespace as mihomo's own connections, so it needs
	// no masquerade here — mihomo dials the exits from the namespace address, and
	// the host masquerades that on the way out.
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	// A permissive policy is right here and nowhere else: the only thing that can
	// reach this namespace is what the host routes into it over the veth, and the
	// host's own drop-policy input chain has already had its say.
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}
