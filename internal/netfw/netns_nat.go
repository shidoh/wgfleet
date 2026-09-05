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
	// DirectCIDRs are destinations that must NOT be intercepted: the corporate
	// networks clients route through the master, the management overlay, the exits'
	// own public addresses (an earlier finding — SSH to an exit from a full-tunnel client).
	//
	// On the host these have always been `ip daddr !=` guards on the interception
	// rules. Routing the whole client interface into a namespace takes them with it,
	// where an unguarded ruleset meets them with an unconditional DNAT for TCP and a
	// fail-closed drop for UDP. This is the second of two lines of defence — the
	// first is a routing rule that keeps them out of the namespace altogether — and
	// it is here because the failure is the same shape as the outage this whole
	// change exists to end: partial, one-way, and invisible to every component
	// metric.
	DirectCIDRs []string
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

	guards, err := privateGuards(in.DirectCIDRs)
	if err != nil {
		return "", err
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
	fmt.Fprintf(&b, "\t\tiifname %q%s ip protocol tcp dnat to %s\n", in.PeerIface, guards, in.RedirAddr)
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain client_udp_tproxy {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// `tproxy` BEFORE `meta mark set`, and the order is load-bearing exactly as it
	// is on the host: nft_tproxy_eval returns NFT_BREAK when no transparent socket
	// is listening, which ends the rule — so a mark written first would ride on a
	// packet that was never intercepted and send it somewhere it does not belong.
	fmt.Fprintf(&b, "\t\tiifname %q%s meta l4proto udp tproxy ip to %s meta mark set %#x accept\n",
		in.PeerIface, guards, in.TProxyAddr, TProxyMark)
	// FAIL CLOSED, for the same reason as on the host: an interception that did not
	// happen is a packet that must not travel. Here it matters more, not less —
	// this namespace has a default route to the host, so an unintercepted datagram
	// would leave by the master's own uplink with the client's address on it.
	fmt.Fprintf(&b, "\t\tiifname %q%s meta l4proto udp counter drop\n", in.PeerIface, guards)
	b.WriteString("\t}\n\n")

	// Client traffic leaves this namespace as mihomo's own connections, so it needs
	// no masquerade here — mihomo dials the exits from the namespace address, and
	// the host masquerades that on the way out.
	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter; policy accept;\n")
	// A permissive policy is right here and nowhere else: the only thing that can
	// reach this namespace is what the host routes into it over the veth, and the
	// host's own drop-policy input chain has already had its say.
	//
	// The one exception is the invalid-state drop, which is not about who may come
	// in. A late FIN retransmit whose conntrack entry has aged out carries no NAT
	// binding; upstream then holds a return path for the untranslated address,
	// conntrack resolves the resulting tuple collision by rewriting the source port,
	// and the far end receives data on a port it never dialled and resets. Traced
	// end to end on an exit 2026-07-27, fixed there with this rule, and the reason
	// it belongs in every namespace that forwards client traffic.
	b.WriteString("\t\tct state invalid drop\n")
	b.WriteString("\t}\n\n")

	// Everything that is NOT TCP or UDP. ICMP, GRE, ESP: the prerouting rules above
	// never see them, so they reach the forward hook and go on to the host, which
	// masquerades them exactly as it did before the move.
	//
	// The chain exists to make that sentence checkable. Before it, "client ICMP
	// still works" was an assumption with nothing behind it — and the client-path
	// prober cannot settle it either, because its gateway ping is answered locally
	// and never comes near here. A counter turns a regression from invisible into a
	// number that stops moving.
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q counter\n", in.PeerIface)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}
