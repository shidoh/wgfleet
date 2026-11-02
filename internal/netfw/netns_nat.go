package netfw

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	// ClientCIDR is the client pool, and it scopes the interception to traffic that
	// came FROM a client.
	//
	// Without it the rules match everything arriving on the veth, which includes
	// every answer mihomo is waiting for: the WireGuard packets coming back from an
	// exit, its own DNS replies, a geo-database download. Those are addressed to the
	// namespace itself, no transparent socket matches them, and the fail-closed drop
	// underneath eats them. Measured on the stand 2026-09-05: client UDP was
	// intercepted and proxied correctly, and mihomo could not resolve a single name
	// because its own answers were being dropped one hook before it — 27 datagrams
	// in a minute, on the rule written to prevent leaks.
	//
	// The host ruleset has always been scoped this way, by `iifname <client iface>`.
	// In here the interface is shared by both directions, so the source is what
	// separates them.
	ClientCIDR string
	// DirectCIDRs are destinations that must NOT be intercepted: the corporate
	// networks clients route through the master, the management overlay, the exits'
	// own public addresses (SSH to an exit from a full-tunnel client).
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
	// SelfAddr is the namespace's own address — where mihomo listens. Traffic
	// addressed to it is FOR mihomo, never traffic to be pushed THROUGH it.
	//
	// This is the exact sibling of the host ruleset's `ip daddr != <gateway>` guard,
	// and it was missing. It matters the moment anything on the host redirects an
	// admin connection in here: the host rewrites the destination to this address,
	// the packet arrives with a destination no direct-CIDR guard covers any more,
	// the interception below claims it and sends it to the redirect port — and
	// mihomo, asked to proxy a connection to itself, closes it. Measured on the live
	// master 2026-09-05: the dashboard's TCP handshake completed and was immediately
	// FIN'd, from the client tunnel only.
	SelfAddr string
	// ClientForwardedPorts are the TCP ports on SelfAddr that the HOST forwards in
	// here on behalf of clients — the Clash API port when the operator has opened it
	// in client_admin_ports. They are admitted by the input closure below alongside
	// the redirect port. Computed by ClientForwardedPorts, never listed by hand: the
	// host's DNAT is rendered from the same call, so the door and the room agree.
	ClientForwardedPorts []int
	// OperatorAPIAddr is the address the operator knows mihomo's control API by —
	// the management-overlay address, which lives on the HOST. Set together with
	// ClientForwardedPorts it redirects a connection DIALLED IN HERE for that
	// address back to SelfAddr.
	//
	// The host's redirect covers what arrives over the mgmt overlay and the client
	// tunnel. It cannot cover a client whose connection mihomo itself carries — a
	// VLESS client, handed over by xray — because that dial starts in this
	// namespace: it reaches the host's management address, where nothing has
	// listened on the API port since the move, and is refused. Redirecting it on
	// the host would send it back in with this namespace's own address as source.
	// Measured on the live master 2026-10-12: 200 over AmneziaWG, an empty reply
	// over VLESS, same URL.
	OperatorAPIAddr string
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
// portOf returns the port half of a host:port, so a rule can name it without the
// address that would make it a different rule.
func portOf(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return port, nil
}

func RenderNetnsNAT(in NetnsNATInput) (string, error) {
	// SelfAddr and the redirect's port are required, not optional: without them the
	// two rules that close mihomo's own listeners to clients are the only thing that
	// silently does not get rendered, and what is left behind is an accept-policy
	// input chain in a namespace every client has a route to. A half-rendered
	// firewall must be a failed render.
	if in.SelfAddr == "" {
		return "", fmt.Errorf("netfw netns NAT: namespace address is required")
	}
	if _, perr := portOf(in.RedirAddr); perr != nil && in.RedirAddr != "" {
		return "", fmt.Errorf("netfw netns NAT: redirect address %q has no port: %w", in.RedirAddr, perr)
	}
	if in.PeerIface == "" || in.RedirAddr == "" || in.TProxyAddr == "" {
		return "", fmt.Errorf("netfw netns NAT: peer interface, redir and tproxy addresses are required")
	}
	if in.ClientCIDR == "" {
		return "", fmt.Errorf("netfw netns NAT: the client pool is required to scope the interception")
	}
	clientCIDR, err := canonicalPrefix(in.ClientCIDR)
	if err != nil {
		return "", fmt.Errorf("netfw netns NAT: invalid client CIDR %q: %w", in.ClientCIDR, err)
	}
	// From a client, and NOT from the gateway.
	//
	// The gateway is the master's own address inside the client pool, so it is where
	// the fleet resolver answers from — and its replies land on this veth with a
	// source inside the pool, match a scope written as "from a client", get handed
	// to a transparent socket that does not exist, and die on the fail-closed drop
	// underneath. Measured on the stand 2026-09-05: 24 datagrams a minute, mihomo
	// unable to resolve a single name, and every TCP probe failing with the tunnel
	// and the interception both working perfectly.
	//
	// It is the same exclusion the host ruleset makes with `ip daddr != <gateway>`,
	// seen from the other end: there the gateway is a destination clients must be
	// able to reach, here it is a source whose packets are answers rather than
	// requests.
	scope := fmt.Sprintf("ip saddr %s", clientCIDR)
	if gw, gerr := gatewayAddr(clientCIDR); gerr == nil {
		scope += fmt.Sprintf(" ip saddr != %s", gw)
	}

	guards, gerr := privateGuards(in.DirectCIDRs)
	if gerr != nil {
		return "", gerr
	}
	if in.SelfAddr != "" {
		addr, aerr := netip.ParseAddr(in.SelfAddr)
		if aerr != nil {
			return "", fmt.Errorf("netfw netns NAT: invalid namespace address %q: %w", in.SelfAddr, aerr)
		}
		guards += fmt.Sprintf(" ip daddr != %s", addr)
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
	fmt.Fprintf(&b, "\t\tiifname %q %s%s ip protocol tcp dnat to %s\n", in.PeerIface, scope, guards, in.RedirAddr)
	b.WriteString("\t}\n\n")

	// Same list as the host's client-tunnel redirect and the input closure below:
	// the port is redirected only when the operator opened it to clients.
	if in.OperatorAPIAddr != "" && len(in.ClientForwardedPorts) > 0 {
		b.WriteString("\tchain output {\n")
		// Numeric, as on the host: the name `dstnat` is refused outside prerouting
		// by the nft the agent validates with, and a refused ruleset fails the pass.
		b.WriteString("\t\ttype nat hook output priority -100; policy accept;\n")
		for _, ap := range in.ClientForwardedPorts {
			fmt.Fprintf(&b, "\t\tip daddr %s tcp dport %d dnat to %s:%d\n", in.OperatorAPIAddr, ap, in.SelfAddr, ap)
		}
		b.WriteString("\t}\n\n")
	}

	b.WriteString("\tchain client_udp_tproxy {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	// `tproxy` BEFORE `meta mark set`, and the order is load-bearing exactly as it
	// is on the host: nft_tproxy_eval returns NFT_BREAK when no transparent socket
	// is listening, which ends the rule — so a mark written first would ride on a
	// packet that was never intercepted and send it somewhere it does not belong.
	fmt.Fprintf(&b, "\t\tiifname %q %s%s meta l4proto udp tproxy ip to %s meta mark set %#x accept\n",
		in.PeerIface, scope, guards, in.TProxyAddr, TProxyMark)
	// FAIL CLOSED, for the same reason as on the host: an interception that did not
	// happen is a packet that must not travel. Here it matters more, not less —
	// this namespace has a default route to the host, so an unintercepted datagram
	// would leave by the master's own uplink with the client's address on it.
	fmt.Fprintf(&b, "\t\tiifname %q %s%s meta l4proto udp counter drop\n", in.PeerIface, scope, guards)
	b.WriteString("\t}\n\n")

	// Client traffic leaves this namespace as mihomo's own connections, so it needs
	// no masquerade here — mihomo dials the exits from the namespace address, and
	// the host masquerades that on the way out.
	// Client traffic that the interception never claimed — ICMP, GRE, ESP — is
	// forwarded straight back out to the host, and it has to leave this namespace
	// wearing the namespace's address.
	//
	// Without this it wears the client's, and then it dies: the host's masquerade is
	// scoped `oifname != <veth>`, so the first postrouting pass (host → namespace)
	// is exempt and conntrack records "no NAT" for the whole connection. The second
	// pass, namespace → uplink, is the same connection: NAT will not fire, the source
	// is still a client's, and the host's egress_leak_guard eats it. Measured on the
	// live master 2026-09-05: 201 packets forwarded in here, 200 dropped there —
	// client ping and traceroute black-holed since the move, in silence.
	//
	// The consequence is worth stating plainly, because it is a choice: these
	// packets leave by the MASTER's address, not through an exit, so a traceroute
	// from a client ends at the master. The operator asked for a working ping over a
	// silent hole, and this is what that costs.
	fmt.Fprintf(&b, "\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "\t\toifname %q %s counter masquerade\n", in.PeerIface, scope)
	b.WriteString("\t}\n\n")

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
	// A client may reach exactly one thing on this namespace's own address: the
	// port its intercepted TCP was redirected to. Everything else mihomo binds here
	// is for the HOST — the SOCKS bridge xray dials, the control API the agent
	// steers mihomo through — and the host is not in the client pool, so it is not
	// affected by either rule below.
	//
	// Without this the rule at pref 400 hands every client a route to this address
	// and the chain's accept policy does the rest: from a client namespace,
	// `curl -x socks5h://<ns>:7893` proxies, with no authentication, and the API
	// answers on 9090 (a secret is all that stands there). The clients are the party
	// this whole interception exists to serve; they are also the least trusted one
	// on the box.
	redirPort, perr := portOf(in.RedirAddr)
	if perr != nil {
		return "", fmt.Errorf("netfw netns NAT: redirect address %q has no port: %w", in.RedirAddr, perr)
	}
	// Plus whatever the host forwards in here for clients (the dashboard, when the
	// operator opened it): a port the host DNATs to this address and this chain then
	// drops is the exact regression measured on the live master 2026-09-06.
	rp, aerr := strconv.Atoi(redirPort)
	if aerr != nil {
		return "", fmt.Errorf("netfw netns NAT: redirect port %q is not a number: %w", redirPort, aerr)
	}
	allowed := append([]int{rp}, in.ClientForwardedPorts...)
	fmt.Fprintf(&b, "\t\t%s ip daddr %s tcp dport != %s counter drop\n", scope, in.SelfAddr, tcpPortSet(allowed...))
	fmt.Fprintf(&b, "\t\t%s ip daddr %s meta l4proto != tcp counter drop\n", scope, in.SelfAddr)
	b.WriteString("\t}\n\n")

	// Everything that is NOT TCP or UDP. ICMP, GRE, ESP: the prerouting rules above
	// never see them, so they reach the forward hook and go back out to the host.
	//
	// What happens to them THERE is not what this comment used to claim. It said the
	// host masquerades them exactly as before the move; it does not. The host's
	// masquerade is scoped `oifname != <veth>`, so the first postrouting pass — the
	// one that sends the packet INTO this namespace — is exempt, and conntrack
	// records that decision for the whole connection. The second pass, out of the
	// namespace and onto the uplink, is the same connection: NAT will not fire, the
	// source is still the client's, and the host's egress_leak_guard eats it.
	//
	// Measured on the live master 2026-09-05: 201 packets counted in here, 200
	// counted by that guard on the way out. Client ping and traceroute have been
	// black-holed since the move, in silence, and this counter is the only place the
	// two halves can be compared. Whether that traffic should leave at all — masked
	// as the master, which is what a masquerade in this namespace would produce — is
	// an open question for the operator, not one to settle in a comment.
	//
	// The chain exists to make that sentence checkable. Before it, "client ICMP
	// still works" was an assumption with nothing behind it — and the client-path
	// prober cannot settle it either, because its gateway ping is answered locally
	// and never comes near here. A counter turns a regression from invisible into a
	// number that stops moving.
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q %s counter\n", in.PeerIface, scope)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}
