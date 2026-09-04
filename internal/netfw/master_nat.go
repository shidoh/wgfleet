package netfw

import (
	"fmt"
	"net/netip"
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
	// TProxyAddr is mihomo's TPROXY listener, e.g. "10.80.0.1:7896". Empty ⇒ render
	// no UDP interception at all, which is the pre-TPROXY behaviour: an agent whose
	// mihomo has no tproxy-port must not have client UDP steered into a socket that
	// is not there.
	TProxyAddr string
	// PrivateCIDRs are destinations that bypass the DNAT (kept DIRECT): RFC1918,
	// CGNAT, mgmt overlay. Rendered as `ip daddr != <cidr>` guards.
	PrivateCIDRs []string
	// NetnsGateway, when set, moves the interception OUT of this ruleset: client
	// traffic is routed to mihomo's namespace instead, and the rules that catch it
	// are rendered there (RenderNetnsNAT).
	//
	// The two cannot both be present. `tproxy` hands the packet to a socket in the
	// current namespace, so leaving the host rule in place would intercept into
	// listeners that have moved — TCP to a refused connection and UDP into the
	// fail-closed drop, which is every client's traffic gone.
	NetnsGateway string
	// NetnsHostIface is the veth end the routed traffic leaves by. Required with
	// NetnsGateway; the masquerade and the leak guard must both exempt it.
	NetnsHostIface string
}

// TProxyMark is the fwmark TPROXY'd client packets carry so policy routing can
// send them to the local table instead of out an uplink. Distinct from
// routing.EffectiveFwMark's client mark, which lives on EXITS and means something
// else entirely; a shared value would make two unrelated policies collide the
// first time a node ever played both roles.
const TProxyMark = 0x2

// TProxyTable is the routing table holding the `local default` route that keeps a
// marked packet on this host so the transparent socket can accept it.
const TProxyTable = 51821

// NetnsRouteTable carries the default route into mihomo's namespace once client
// interception lives there. Numbered next to its siblings — 51820 is the exits'
// egress table, 51821 the master's TPROXY table — rather than something low like
// 100, which is already an ip-rule PRIORITY on every exit and would be read as
// one at a glance.
const NetnsRouteTable = 51822

// NetnsRulePref is the ip-rule priority that sends client traffic to
// NetnsRouteTable. Explicit, unlike the master's existing TPROXY rule, which was
// added without one and landed at 32765 by accident of insertion order: a second
// unnumbered rule would sit at 32764 and their relative order would then change
// across a re-apply.
const NetnsRulePref = 400

// RenderMasterNAT renders the master's nft NAT ruleset: drop client QUIC, DNAT
// non-private client TCP to mihomo, and MASQUERADE client traffic outbound.
func RenderMasterNAT(in MasterNATInput) (string, error) {
	if in.ClientInterface == "" || in.ClientCIDR == "" || in.RedirAddr == "" {
		return "", fmt.Errorf("netfw master NAT: client interface, CIDR and redir addr are required")
	}

	guards, err := privateGuards(in.PrivateCIDRs)
	if err != nil {
		return "", err
	}
	// Canonicalize the client pool from its parsed form so a malformed or crafted
	// ClientCIDR can never inject nft syntax into this root-applied ruleset.
	clientCIDR, err := canonicalPrefix(in.ClientCIDR)
	if err != nil {
		return "", fmt.Errorf("netfw master NAT: invalid client CIDR %q: %w", in.ClientCIDR, err)
	}

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Rendered by wgfleet — master NAT (mihomo DNAT + MASQUERADE). Do not edit by hand.\n")
	// Atomically REPLACE our table rather than appending to it. Without the
	// delete-first idiom, `nft -f` adds the chains' rules to the EXISTING chains on
	// every re-apply, so DNAT/masquerade rules accumulate and stale rules from an
	// older binary (e.g. a previous `oifname "ens3"` masquerade) linger forever
	// (observed live 2026-06-18). `table` ensures it exists so `delete` never fails;
	// the whole script is one atomic nft transaction, so there is no unprotected
	// window. Mirrors RenderRuleset's handling of the filter table.
	fmt.Fprintf(&b, "table ip %s\n", MasterNATTable)
	fmt.Fprintf(&b, "delete table ip %s\n", MasterNATTable)
	fmt.Fprintf(&b, "table ip %s {\n", MasterNATTable)

	// The gateway's OWN address in the client pool is never a proxy destination:
	// traffic a client sends there is a request to a service the master runs FOR
	// its clients (the self-service portal, the local resolver), not internet
	// traffic to be routed through an exit. Without this guard the redirect below
	// swallows it and the service simply never answers — found on a rehearsal,
	// where it made the client portal unreachable by construction.
	gatewayGuard := ""
	if gw, err := gatewayAddr(in.ClientCIDR); err == nil {
		gatewayGuard = fmt.Sprintf(" ip daddr != %s", gw)
	}

	b.WriteString("\tchain prerouting {\n")
	b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	// Client QUIC is PROXIED now, not dropped.
	//
	// Dropping UDP/443 was a stand-in for having no UDP path at all: with only a TCP
	// redirect, QUIC could either leave the master's own uplink or be killed so
	// browsers fell back to TCP, and killing it was the better of the two. TPROXY
	// removed that choice, and keeping the drop turned it into a trap — the drop sits
	// at the `dstnat` hook (priority -100) while the interception sits at `mangle`
	// (-150), so despite reading first in this file it runs SECOND and shadows it.
	// Measured on a rehearsal: client UDP to :5353 and :4433 reached an exit, while
	// :443 produced no mihomo entry and nothing on the tunnel at all. Every client's
	// HTTP/3 black-holed until it timed out into TCP — itself a distinctive shape —
	// while mihomo's sniffer was configured to handle QUIC on exactly that port.
	//
	// The drop is only correct when there is no UDP path; TProxyAddr is precisely the
	// statement that there is one.
	if in.TProxyAddr == "" {
		fmt.Fprintf(&b, "\t\tiifname %q%s udp dport 443 drop\n", in.ClientInterface, guards)
	}
	// DNAT non-private client TCP to mihomo's redir-port.
	if in.NetnsGateway == "" {
		fmt.Fprintf(&b, "\t\tiifname %q%s%s ip protocol tcp dnat to %s\n", in.ClientInterface, guards, gatewayGuard, in.RedirAddr)
	}
	b.WriteString("\t}\n\n")

	// Client UDP, intercepted rather than NAT'd.
	//
	// The redirect above is TCP-only, and everything else a client sent over UDP used
	// to traverse the forward chain, get masqueraded and leave the MASTER's uplink —
	// so DNS to a foreign resolver, QUIC on a non-443 port, WebRTC and games all
	// egressed from the master's own address instead of an exit's. TPROXY is the
	// right tool because it does NOT rewrite the packet: mihomo reads the original
	// destination off a transparent socket, which is exactly what a proxy needs.
	//
	// ONE chain, and the statement order inside its rule is load-bearing.
	//
	// `tproxy` comes BEFORE `meta mark set`. nft_tproxy_eval returns NFT_BREAK when
	// the socket lookup finds no transparent listener, which ends evaluation of the
	// rule — so with the mark written first, a packet that FAILED to be intercepted
	// still carried mark 0x2. That mark is consumed by the policy route
	// (`fwmark 0x2 lookup 51821` → `local default dev lo`) two hooks later, which
	// makes the kernel treat the packet as locally destined and hand it to the input
	// chain, where `meta mark 0x2 accept` waved it past a `policy drop` and delivered
	// it to whatever wildcard-bound socket matched the port. Every mihomo restart —
	// a compose change, mihomoRedirPlanner, mihomoWGDupPlanner — opened that window,
	// and on a stock box systemd-resolved is listening on 0.0.0.0:5353. With the mark
	// written only after a successful interception, a failed lookup degrades to what
	// the world was before TPROXY existed: the datagram is forwarded and masqueraded.
	//
	// There is no companion divert chain. The usual `socket transparent 1` chain at
	// mangle-10 is a TCP idiom: it re-marks packets belonging to an ESTABLISHED
	// transparent socket. For UDP the lookup uses the packet's ORIGINAL tuple
	// (client → 8.8.8.8:53), and mihomo's transparent sockets are bound to the
	// gateway address, so it never matched an intercepted flow — nothing was leaking
	// for it to catch, since this chain has no ct-state guard and re-intercepts every
	// packet anyway. What it DID match was client datagrams addressed to mihomo's own
	// listeners, which the guard below deliberately excludes and the input drop policy
	// would otherwise eat; accepting those is the an earlier finding self-dial shape.
	if in.TProxyAddr != "" && in.NetnsGateway == "" {
		b.WriteString("\tchain client_udp_tproxy {\n")
		b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname %q%s%s meta l4proto udp tproxy ip to %s meta mark set %#x accept\n",
			in.ClientInterface, guards, gatewayGuard, in.TProxyAddr, TProxyMark)
		// FAIL CLOSED. The rule above ends at NFT_BREAK when no transparent socket is
		// listening — every mihomo restart — and without this second rule the datagram
		// simply falls through to the forward chain and the masquerade, i.e. it leaves
		// the MASTER's own uplink. Measured on the stand: stop the container and the
		// client's DNS keeps working, sourced from the master's public address instead
		// of an exit's. That is the precise failure this whole chain exists to end, and
		// it is worse than an outage, because the user cannot see it. An interception
		// that did not happen is a packet that must not travel.
		//
		// Scoped identically to the rule above, so it can only ever catch traffic that
		// rule was meant to take: the private-destination and gateway exemptions still
		// go DIRECT, and everything the master itself sends is on another interface.
		fmt.Fprintf(&b, "\t\tiifname %q%s%s meta l4proto udp counter drop\n",
			in.ClientInterface, guards, gatewayGuard)
		b.WriteString("\t}\n\n")
	}

	b.WriteString("\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	// MASQUERADE client traffic on EVERY egress except back into the client
	// interface itself. Client packets leave by more than one uplink: the public
	// link (internet) AND the mgmt/ZT overlay (DNS to the exits' blocky, internal
	// nets). Pinning a single egress iface (e.g. ens3) silently breaks the overlay
	// path — DNS dies because blocky sees the un-NAT'd client source and can't
	// route the reply back (the reference deployment §3.12 masquerades both ens3 and the ZT iface).
	// The veth to mihomo's namespace is exempted for a reason that is not obvious
	// and is fatal to miss: TPROXY works precisely because it does NOT rewrite the
	// packet — mihomo reads the original (client, server) pair off the transparent
	// socket to know who to answer. Masquerading on the way in would present every
	// client as the host end of the veth, and mihomo could not return a single
	// reply to the right one.
	fmt.Fprintf(&b, "\t\tip saddr %s oifname != %q%s masquerade\n",
		clientCIDR, in.ClientInterface, netnsIfaceGuard(in.NetnsHostIface))
	b.WriteString("\t}\n")

	// Enforce what the masquerade above promises: no client-pool source ever reaches
	// the wire. Sibling of the exit's egress_leak_guard, and here for the same reason
	// — NAT is applied per CONNECTION, so a packet conntrack cannot place (a late FIN
	// retransmit whose entry already aged out, an out-of-window segment) carries no
	// NAT binding and would leave with a client's private address. Upstream then holds
	// a return path for it, later replies come back addressed to it, and conntrack
	// resolves the resulting tuple collision by rewriting the TCP source port — the
	// far end receives data on a port it never dialed and resets. Traced end-to-end on
	// an exit 2026-07-27; the master masquerades its client pool the same way, for
	// split-tunnel traffic that bypasses mihomo, so the same failure is available here.
	//
	// This chain runs AFTER srcnat, so every packet NAT did translate has already
	// stopped matching; a pool address surviving to this point is by definition one NAT
	// never saw. It mirrors the masquerade's scope exactly (same pool, same
	// `oifname != <client iface>`), so it cannot fire on legitimate traffic, and it is
	// deliberately redundant with `ct state invalid drop` in the filter table's forward
	// chain: that rule removes the known cause, this one asserts the outcome regardless
	// of cause.
	b.WriteString("\n\tchain egress_leak_guard {\n")
	b.WriteString("\t\ttype filter hook postrouting priority srcnat + 10; policy accept;\n")
	// Two exclusions, both measured rather than reasoned, and both missing here long
	// after the exit's copy of this rule grew them:
	//
	//   - `oifname != "lo"`. Anything on the master that dials the gateway address
	//     routes over loopback with the gateway as its SOURCE, matches "not wg0", and
	//     is dropped. That address is where the client portal and the local resolver
	//     live — the two services this file's own DNAT exception exists to protect —
	//     so the master could not reach its own services. Measured on a rehearsal:
	//     `curl http://<gw>:7895/` timed out and the guard's counter moved by seven.
	//   - `ip saddr != <gateway>`. The gateway is inside the client pool, so traffic
	//     the master ORIGINATES from it is caught by a rule meant for traffic it
	//     FORWARDS on a client's behalf. On the exit, counting those made a healthy
	//     node report half a million leaks.
	//   - `oifname != <veth>` once the interception moved. This chain runs AFTER
	//     srcnat, so today it never fires on client traffic only because the
	//     masquerade above already rewrote the source. Exempting the veth there and
	//     not here turns a partial failure into a total one: the source stays in the
	//     client pool, the guard matches, and every client packet routed to the
	//     namespace is dropped one hook later.
	fmt.Fprintf(&b, "\t\tip saddr %s%s oifname != %q oifname != \"lo\"%s counter drop\n",
		clientCIDR, gatewaySourceGuard(in.ClientCIDR), in.ClientInterface,
		netnsIfaceGuard(in.NetnsHostIface))
	b.WriteString("\t}\n")

	b.WriteString("}\n")
	return b.String(), nil
}

// privateGuards renders the `ip daddr != <cidr>` guard chain that keeps private
// destinations out of the DNAT/drop rules. Each CIDR is parsed and re-emitted in
// canonical form (never the raw input), so a malformed or crafted direct-CIDR
// value cannot inject nft syntax into this root-applied ruleset (CRITICAL —
// these come from the operator manifest's direct_cidrs + derived mgmt CIDRs).
func privateGuards(cidrs []string) (string, error) {
	var b strings.Builder
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		canon, err := canonicalPrefix(c)
		if err != nil {
			return "", fmt.Errorf("netfw master NAT: invalid private CIDR %q: %w", c, err)
		}
		fmt.Fprintf(&b, " ip daddr != %s", canon)
	}
	return b.String(), nil
}

// gatewayAddr returns the master's own address inside the client pool: the first
// host, which is what the client interface is configured with.
func gatewayAddr(clientCIDR string) (string, error) {
	prefix, err := netip.ParsePrefix(clientCIDR)
	if err != nil {
		return "", err
	}
	addr := prefix.Masked().Addr().Next()
	if !addr.IsValid() || !prefix.Contains(addr) {
		return "", fmt.Errorf("client pool %q has no host address", clientCIDR)
	}
	return addr.String(), nil
}

// gatewaySourceGuard renders the `ip saddr != <gateway>` exclusion for the leak
// guard, or "" when the pool has no derivable gateway (in which case the guard is
// merely as strict as it always was, never stricter).
func gatewaySourceGuard(clientCIDR string) string {
	gw, err := gatewayAddr(clientCIDR)
	if err != nil {
		return ""
	}
	return fmt.Sprintf(" ip saddr != %s", gw)
}

// netnsIfaceGuard renders the exemption for the veth to mihomo's namespace, or
// nothing when the interception still lives on this host.
func netnsIfaceGuard(iface string) string {
	if iface == "" {
		return ""
	}
	return fmt.Sprintf(" oifname != %q", iface)
}
