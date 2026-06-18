// Package netfw renders nftables rulesets from the desired FirewallSpec. On MVP
// we render a .nft script and apply it atomically with `nft -f` (ADR per
// docs/DESIGN.md §5): the rendered text is easy to review in dry-run and mirrors what
// we wrote by hand. Native netlink is a later milestone.
package netfw

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Well-known ports kept open on every managed node's input chain.
const (
	sshPort      = 22
	zeroTierPort = 9993 // ZeroTier control/data (UDP)
)

// mgmtOverlayIface is the nft iifname glob matching the management-overlay
// interfaces (ZeroTier's ztXXXXXXXX). Inbound on the overlay is accepted wholesale:
// it is the trust boundary for all management — admin UI, metrics, controller gRPC,
// fleet-internal DNS (docs/DESIGN.md §9/§10) — and the operator reaches nodes over it.
// Accepting the interface is a fail-safe so a missing mgmt entry in the whitelist
// can never lock management out (the failure mode that left a rebooted node
// unreachable until ZeroTier re-converged). If the mgmt overlay is ever abstracted
// off ZeroTier (open question #5), change it here.
const mgmtOverlayIface = "zt*"

// baselineTable is the bootstrap firewall table name (provisioner/templates.go).
// The exit firewall deletes it on apply, superseding it without a global flush.
const baselineTable = "wgfleet_baseline"

// ExitTable is the per-node input-firewall nft table name. Both roles reuse it
// (a node is exactly one role, so there is no collision): the exit's full ruleset
// and the master's input filter both render into `inet wgfleet`. The master's NAT
// lives in a separate table (MasterNATTable, family ip). Exported so the agent can
// probe the live kernel for it (live-kernel reload gate) using the exact name the
// renderer emits.
const ExitTable = "wgfleet"

// RenderInput is the context needed to render a node's firewall.
type RenderInput struct {
	Firewall domain.FirewallSpec
	Role     domain.Role
	// WGReplyMark, when non-zero, renders an nft mangle rule that marks this node's
	// WG-server reply/handshake packets (source port = Firewall.WGPort) with the
	// mark, so the routing `ip rule fwmark <mark> lookup main` keeps them OFF the
	// egress (WARP) interface (an earlier finding: otherwise clients/the master see a
	// Cloudflare source and drop the peer). Set only on egress-routed nodes; the
	// value must equal routing.EffectiveFwMark for the same spec.
	WGReplyMark int
	// ClientCIDR is the exit's WG client pool. When set (exit role), a nat
	// postrouting chain MASQUERADEs client-sourced traffic on egress so packets
	// leaving WARP/wgcf carry the egress interface's address — without it client
	// packets exit with a private source (the master's tunnel IP) and Cloudflare
	// drops them / cannot route the reply back ("empty reply from server").
	ClientCIDR string
	// WGInterface is the exit's WG interface (e.g. "awg0"); the MASQUERADE excludes
	// it (`oifname != <wg>`) so only client→egress traffic is SNAT'd, never replies
	// looping back to clients.
	WGInterface string
	// EgressInterface is the WARP/wgcf interface. When set, an MSS clamp is rendered
	// in the forward chain so TLS through the double encapsulation (client→master→
	// exit→WARP) does not stall when PMTU discovery is blocked (an earlier finding; the reference deployment
	// §4.10's `clamp-mss-to-pmtu`).
	EgressInterface string
	// OverlayMSS, when > 0, renders a postrouting MSS clamp on the management overlay
	// interface (`zt*`): every TCP SYN leaving over ZeroTier has its MSS capped to
	// this fixed value. It is insurance for the control plane (the agent↔controller
	// mTLS channel rides the overlay): if the ZeroTier MTU is left/reset at its 2800
	// default while the underlay path is smaller, large TLS-handshake records (the
	// server certificate) get black-holed and `register` fails with a handshake
	// deadline — exactly the failure we hit. A FIXED clamp (not `rt mtu`, which would
	// read the wrong 2800 interface MTU) keeps the channel working regardless. The
	// clamp only lowers an MSS, so it is a no-op when the overlay MTU is already
	// correct. Agent-local (not from the wire) so it cannot depend on the very
	// channel it protects.
	OverlayMSS int
	// RedirMark identifies the master's client→mihomo redirect for the input chain.
	// On the master, client TCP is DNAT'd in prerouting to the mihomo redir port at
	// the master's OWN address (BindAddress) ⇒ after DNAT the packet routes to the
	// INPUT hook, not FORWARD. With the drop-policy input chain (ADR-0020) the
	// redirected SYN matches no accept rule and is dropped — clients then get pings
	// and DNS (ICMP/forwarded) but no web (every TCP black-holes before mihomo even
	// sees it). When RedirPort > 0 (master role) an accept for
	// `iifname <RedirInterface> tcp dport <RedirPort>` lets the redirect through.
	RedirPort int
	// RedirInterface is the client-facing WG interface whose DNAT'd TCP must reach
	// the local mihomo redir port (master role; defaults to "wg0"). Scoping the
	// accept to this interface keeps clients off the master's other local services
	// (Clash API, wg-easy UI) — only the redirect port is opened, only from clients.
	RedirInterface string
	// ClientAdminPorts are TCP ports (master role) the client pool is allowed to
	// reach on the master's own address: the admin UIs (controller Web UI, mihomo
	// dashboard) that bind the mgmt overlay only. Each renders an accept scoped to
	// the client interface (RedirInterface, default "wg0"), opt-in per master. Empty
	// ⇒ the strict default where only the mgmt overlay reaches admin services.
	ClientAdminPorts []int
	// ClampMSS, when > 0 (exit role), clamps forwarded TCP SYN/SYN-ACK MSS in BOTH
	// directions to this value. Client traffic crosses the master↔exit tunnel
	// (WGServer.MTU, e.g. 1360) AND the egress (WARP). The egress leg alone is NOT
	// the binding hop: clamping only there (the old `oifname <egress> rt mtu` rule)
	// let the server advertise an MSS sized for the looser egress, so its response
	// segments black-holed on the RETURN through the tighter master↔exit tunnel —
	// the classic "connects but empty reply / timeouts" PMTU blackhole (an earlier finding;
	// verified live 2026-06-18: clamp 1320 fixed it). A fixed value (= min(tunnel,
	// egress) − 40) bounds both directions; `rt mtu` cannot, since it only sees the
	// immediate egress interface, not the tighter return hop.
	ClampMSS int
	// ClientMSS, when > 0 (master role), clamps TCP MSS on traffic leaving toward the
	// client interface (RedirInterface, default "wg0") to this fixed value. The master
	// is the only node that sees ALL client traffic AND knows the true client MTU (the
	// minimum across every hop — client↔master, master↔exit, exit→WARP — i.e.
	// spec.WGServer.MTU). The exit's ClampMSS only bounds the exit/WARP hops, so it can
	// advertise an MSS sized for the looser 1360 master↔exit tunnel that then
	// black-holes on the tighter 1320 client hop; and master-LOCAL traffic (SSH to the
	// master host, the mgmt-bound admin UIs) is forwarded by nothing and so is clamped
	// nowhere. Without this, large server→client segments (SSH KEX, dashboard HTML, any
	// sustained download) black-hole while pings/DNS/short requests survive — the
	// "connects but hangs / can't SSH to the master / throughput stalls" symptom
	//. A postrouting clamp catches both forwarded and locally
	// originated SYN/SYN-ACK toward the client; it only lowers an MSS, so it is a no-op
	// when nothing exceeds it. Value = spec.WGServer.MTU − 40.
	ClientMSS int
}

// RenderRuleset renders an nftables script for in. The input chain defaults to
// drop: only established/related, loopback, the management overlay (ZeroTier
// interface, fail-safe), the whitelist, SSH, the ZeroTier transport port and the
// WG port are accepted. An AS-blacklist set is declared (and dropped early) when
// enabled; it is populated out-of-band from ASN feeds, so the rule references an
// initially empty set rather than inlining thousands of prefixes.
// mssClampExpr renders the nft match+statement that clamps the TCP MSS of SYN /
// SYN-ACK packets DOWN to mss. The `tcp option maxseg size > mss` guard is ESSENTIAL:
// nft's `tcp option maxseg size set` is UNCONDITIONAL (unlike iptables
// --clamp-mss-to-pmtu), so without the guard it RAISES a peer's already-smaller MSS
// up to mss. That black-holes large segments whenever the real path is tighter than
// mss — observed live 2026-06-18 when the client MTU was lowered to 1280 (advertising
// MSS ~1240) and the clamp set it back to 1280/1320, so TLS certs and downloads died
// while ping/DNS survived. With the guard the rule only ever lowers — a true clamp.
func mssClampExpr(mss int) string {
	return fmt.Sprintf("tcp flags syn / syn,rst tcp option maxseg size > %d tcp option maxseg size set %d", mss, mss)
}

func RenderRuleset(in RenderInput) (string, error) {
	if in.Firewall.WGPort <= 0 || in.Firewall.WGPort > 65535 {
		return "", fmt.Errorf("netfw render: invalid WG port %d", in.Firewall.WGPort)
	}
	v4Whitelist, err := splitWhitelist(in.Firewall.Whitelist)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	b.WriteString("# Rendered by wgfleet — do not edit by hand.\n")
	// Supersede the bootstrap baseline (its allow-set is a subset of this firewall)
	// and atomically replace our own table — WITHOUT `flush ruleset`, which would
	// also wipe unrelated tables (e.g. the master NAT on a co-located node, or this
	// table on a re-provision that re-applies the baseline). `table X` ensures the
	// table exists so the following `delete` never fails; the whole script is one
	// atomic nft transaction, so there is no window with no firewall.
	fmt.Fprintf(&b, "table inet %s\n", baselineTable)
	fmt.Fprintf(&b, "delete table inet %s\n", baselineTable)
	fmt.Fprintf(&b, "table inet %s\n", ExitTable)
	fmt.Fprintf(&b, "delete table inet %s\n\n", ExitTable)
	fmt.Fprintf(&b, "table inet %s {\n", ExitTable)

	if in.Firewall.ASBlacklist {
		b.WriteString("\tset as_blacklist {\n")
		b.WriteString("\t\ttype ipv4_addr\n")
		b.WriteString("\t\tflags interval\n")
		b.WriteString("\t\t# populated out-of-band from ASN scanner feeds\n")
		b.WriteString("\t}\n\n")
	}

	b.WriteString("\tset whitelist {\n")
	b.WriteString("\t\ttype ipv4_addr\n")
	b.WriteString("\t\tflags interval\n")
	if len(v4Whitelist) > 0 {
		fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(v4Whitelist, ", "))
	}
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority 0; policy drop;\n")
	b.WriteString("\t\tct state established,related accept\n")
	b.WriteString("\t\tct state invalid drop\n")
	b.WriteString("\t\tiif \"lo\" accept\n")
	// Trust the management overlay wholesale (fail-safe; see mgmtOverlayIface).
	fmt.Fprintf(&b, "\t\tiifname %q accept\n", mgmtOverlayIface)
	b.WriteString("\t\tip saddr @whitelist accept\n")
	if in.Firewall.ASBlacklist {
		b.WriteString("\t\tip saddr @as_blacklist drop\n")
	}
	fmt.Fprintf(&b, "\t\ttcp dport %d accept\n", sshPort)
	fmt.Fprintf(&b, "\t\tudp dport %d accept\n", zeroTierPort)
	fmt.Fprintf(&b, "\t\tudp dport %d accept\n", in.Firewall.WGPort)
	// Master only: let client TCP that prerouting DNAT'd to the local mihomo redir
	// port reach mihomo. After DNAT the destination is the master's own address, so
	// the packet hits this INPUT chain; without this accept the drop policy swallows
	// every redirected web connection while ICMP/DNS still work (an earlier finding sibling).
	if in.Role == domain.RoleMaster {
		redirIface := in.RedirInterface
		if redirIface == "" {
			redirIface = "wg0"
		}
		if in.RedirPort > 0 {
			fmt.Fprintf(&b, "\t\tiifname %q tcp dport %d accept\n", redirIface, in.RedirPort)
		}
		// Opt-in: expose admin UIs (controller Web UI, mihomo dashboard) bound to the
		// mgmt overlay to the client pool. Without these the drop policy swallows
		// client TCP to those ports (clients get pings/DNS/web but no dashboards). The
		// destination must also bypass the client→mihomo DNAT, which it does when the
		// mgmt address sits under the master's DirectCIDRs (e.g. 172.16.0.0/12).
		for _, port := range in.ClientAdminPorts {
			if port <= 0 || port > 65535 {
				continue
			}
			fmt.Fprintf(&b, "\t\tiifname %q tcp dport %d accept\n", redirIface, port)
		}
	}
	b.WriteString("\t\ticmp type echo-request accept\n")
	b.WriteString("\t\ticmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept\n")
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")
	// MSS clamp for TLS/large transfers through the nested encapsulation
	// (client→master→exit→WARP). Clamp BOTH directions to a fixed size bounded by the
	// tightest tunnel along the client path — not just the egress (see ClampMSS).
	if in.ClampMSS > 0 {
		fmt.Fprintf(&b, "\t\t%s\n", mssClampExpr(in.ClampMSS))
	}
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority 0; policy accept;\n")
	b.WriteString("\t}\n")

	// Mark WG-server reply/handshake packets so source routing keeps them direct
	//. `type route hook output` re-runs the route lookup after the
	// mark is set, so the routing `ip rule fwmark` actually diverts them to the main
	// table instead of the egress (WARP) interface. Only emitted on egress-routed
	// nodes (WGReplyMark != 0).
	if in.WGReplyMark != 0 {
		b.WriteString("\n\tchain mangle_output {\n")
		b.WriteString("\t\ttype route hook output priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\tmeta l4proto udp udp sport %d meta mark set 0x%x\n", in.Firewall.WGPort, in.WGReplyMark)
		b.WriteString("\t}\n")
	}

	// Clamp TCP MSS on the management overlay (control-plane insurance, see
	// OverlayMSS). Postrouting catches locally-originated SYNs (the agent dialing the
	// controller) as well as any forwarded traffic. A FIXED size, not `rt mtu`: the
	// whole point is to survive a too-large ZeroTier interface MTU, so reading the
	// interface MTU would defeat it.
	if in.OverlayMSS > 0 {
		b.WriteString("\n\tchain mgmt_overlay_mss {\n")
		b.WriteString("\t\ttype filter hook postrouting priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\toifname %q %s\n", mgmtOverlayIface, mssClampExpr(in.OverlayMSS))
		b.WriteString("\t}\n")
	}

	// Clamp TCP MSS toward the client interface to the true client-path MTU (master
	// role; see ClientMSS). The master is the single choke point that sees every
	// client flow — to the internet via an exit, to the master's own services, and to
	// the mgmt overlay — and the only one that knows the tightest hop. Postrouting on
	// the client interface catches the master→client SYN-ACK for ALL of them
	// (locally-terminated and forwarded), so large segments never black-hole on the
	// tight client tunnel. Without it the exit's own clamp is too loose for the client
	// hop and master-local traffic is unclamped entirely.
	//
	// Clamp in BOTH directions across the client interface. Postrouting (oifname)
	// rewrites the master→client SYN-ACK MSS — bounding what the CLIENT sends — while
	// prerouting (iifname) rewrites the client→master SYN MSS, bounding what the MASTER
	// sends back. Both are needed: the reported black-hole is large MASTER→client
	// segments (download data, the SSH server's KEX, dashboard HTML), which are limited
	// by the MSS the CLIENT advertised in its SYN, so that incoming SYN must be clamped
	// too. A forward-hook clamp (as on the exit) would catch forwarded traffic but miss
	// master-LOCAL connections (sshd, the admin UIs) that terminate on the host and
	// never traverse FORWARD; prerouting+postrouting covers local and forwarded alike.
	if in.Role == domain.RoleMaster && in.ClientMSS > 0 {
		clientIface := in.RedirInterface
		if clientIface == "" {
			clientIface = "wg0"
		}
		b.WriteString("\n\tchain client_mss_in {\n")
		b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\tiifname %q %s\n", clientIface, mssClampExpr(in.ClientMSS))
		b.WriteString("\t}\n")
		b.WriteString("\n\tchain client_mss_out {\n")
		b.WriteString("\t\ttype filter hook postrouting priority mangle; policy accept;\n")
		fmt.Fprintf(&b, "\t\toifname %q %s\n", clientIface, mssClampExpr(in.ClientMSS))
		b.WriteString("\t}\n")
	}

	// MASQUERADE client-sourced traffic on egress (exit role). The exit forwards
	// client traffic out WARP/wgcf (or, on a direct/failover exit, the uplink); the
	// packets arrive with the master's tunnel IP as source (a private address), so
	// without SNAT they leave with a private source and the upstream (Cloudflare for
	// WARP) drops them and cannot route the reply back — the symptom is a TCP that
	// connects but returns nothing. Scoped to the client pool and excluding the WG
	// interface so only client→egress is translated, never replies back to clients.
	if in.Role == domain.RoleExit && in.ClientCIDR != "" {
		wg := in.WGInterface
		if wg == "" {
			wg = "awg0"
		}
		b.WriteString("\n\tchain postrouting {\n")
		b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
		fmt.Fprintf(&b, "\t\tip saddr %s oifname != %q masquerade\n", in.ClientCIDR, wg)
		b.WriteString("\t}\n")
	}

	b.WriteString("}\n")
	return b.String(), nil
}

// splitWhitelist separates IPv4 entries (the MVP set type) from IPv6, erroring
// on anything unparseable so a typo — or a crafted value that would inject nft
// syntax into the rendered ruleset — fails the render rather than being written
// verbatim into `elements = { ... }`. Each entry is parsed as an IP address or a
// CIDR prefix and re-emitted from the parsed value (canonical form), so only
// well-formed addresses ever reach the ruleset. IPv6 is parsed and skipped (a
// dedicated set is a follow-up), never passed through.
func splitWhitelist(entries []string) ([]string, error) {
	var v4 []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		canonical, is4, err := parseWhitelistEntry(e)
		if err != nil {
			return nil, fmt.Errorf("netfw render: invalid whitelist entry %q: %w", e, err)
		}
		if !is4 {
			// IPv6 — a dedicated set is a follow-up; skip with intent, not silently.
			continue
		}
		v4 = append(v4, canonical)
	}
	return v4, nil
}

// parseWhitelistEntry parses a single whitelist entry as either a bare IP address
// or a CIDR prefix and returns its canonical string form plus whether it is IPv4.
// Re-emitting the parsed value (not the raw input) guarantees the rendered nft
// element cannot contain anything but a valid address/prefix.
func parseWhitelistEntry(e string) (canonical string, isV4 bool, err error) {
	if strings.Contains(e, "/") {
		p, perr := netip.ParsePrefix(e)
		if perr != nil {
			return "", false, perr
		}
		return p.Masked().String(), p.Addr().Is4(), nil
	}
	a, aerr := netip.ParseAddr(e)
	if aerr != nil {
		return "", false, aerr
	}
	return a.String(), a.Is4(), nil
}
