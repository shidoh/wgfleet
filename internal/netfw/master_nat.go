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
	// Drop client QUIC so browsers fall back to TCP through mihomo.
	//
	// Kept even now that UDP is intercepted: this rule already prevented the leak
	// for the single largest UDP flow, it is the behaviour the fleet has been tested
	// on, and re-enabling HTTP/3 through TPROXY is a one-line change once the
	// interception itself has been proven under real load. One behavioural change at
	// a time.
	fmt.Fprintf(&b, "\t\tiifname %q%s udp dport 443 drop\n", in.ClientInterface, guards)
	// DNAT non-private client TCP to mihomo's redir-port.
	fmt.Fprintf(&b, "\t\tiifname %q%s%s ip protocol tcp dnat to %s\n", in.ClientInterface, guards, gatewayGuard, in.RedirAddr)
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
	// Two chains, in the order the kernel runs them. The divert chain re-marks
	// packets that already belong to an established transparent socket; without it
	// only the FIRST packet of each flow is intercepted and the rest go back to
	// leaking. The tproxy chain then catches genuinely new flows, honouring the same
	// exemptions the TCP redirect does — private destinations stay DIRECT, and the
	// gateway address belongs to the master's own services, not to the internet.
	if in.TProxyAddr != "" {
		b.WriteString("\tchain client_udp_divert {\n")
		b.WriteString("\t\ttype filter hook prerouting priority mangle - 10; policy accept;\n")
		fmt.Fprintf(&b, "\t\tmeta l4proto udp socket transparent 1 meta mark set %#x accept\n", TProxyMark)
		b.WriteString("\t}\n\n")

		b.WriteString("\tchain client_udp_tproxy {\n")
		b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname %q%s%s meta l4proto udp meta mark set %#x tproxy ip to %s accept\n",
			in.ClientInterface, guards, gatewayGuard, TProxyMark, in.TProxyAddr)
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
	fmt.Fprintf(&b, "\t\tip saddr %s oifname != %q masquerade\n", clientCIDR, in.ClientInterface)
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
	fmt.Fprintf(&b, "\t\tip saddr %s%s oifname != %q oifname != \"lo\" counter drop\n",
		clientCIDR, gatewaySourceGuard(in.ClientCIDR), in.ClientInterface)
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
