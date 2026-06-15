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
	sshPort       = 22
	zeroTierPort  = 9993 // ZeroTier control/data (UDP)
	quicHTTPSPort = 443  // QUIC/HTTPS over UDP, dropped on masters (an earlier finding context)
)

// baselineTable is the bootstrap firewall table name (provisioner/templates.go).
// The exit firewall deletes it on apply, superseding it without a global flush.
const baselineTable = "wgfleet_baseline"

// ExitTable is the exit firewall's nft table name. Exported so the agent can
// probe the live kernel for it (live-kernel reload gate) using the exact name the
// renderer emits.
const ExitTable = "wgfleet"

// RenderInput is the context needed to render a node's firewall.
type RenderInput struct {
	Firewall domain.FirewallSpec
	Role     domain.Role
	// DropQUIC drops inbound UDP/443 (QUIC). Masters do this so clients fall back
	// to TCP paths the router can handle; exits leave it alone.
	DropQUIC bool
	// WGReplyMark, when non-zero, renders an nft mangle rule that marks this node's
	// WG-server reply/handshake packets (source port = Firewall.WGPort) with the
	// mark, so the routing `ip rule fwmark <mark> lookup main` keeps them OFF the
	// egress (WARP) interface (an earlier finding: otherwise clients/the master see a
	// Cloudflare source and drop the peer). Set only on egress-routed nodes; the
	// value must equal routing.EffectiveFwMark for the same spec.
	WGReplyMark int
}

// RenderRuleset renders an nftables script for in. The input chain defaults to
// drop: only established/related, loopback, the whitelist, SSH, ZeroTier and the
// WG port are accepted. An AS-blacklist set is declared (and dropped early) when
// enabled; it is populated out-of-band from ASN feeds, so the rule references an
// initially empty set rather than inlining thousands of prefixes.
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
	b.WriteString("\t\tip saddr @whitelist accept\n")
	if in.Firewall.ASBlacklist {
		b.WriteString("\t\tip saddr @as_blacklist drop\n")
	}
	fmt.Fprintf(&b, "\t\ttcp dport %d accept\n", sshPort)
	fmt.Fprintf(&b, "\t\tudp dport %d accept\n", zeroTierPort)
	fmt.Fprintf(&b, "\t\tudp dport %d accept\n", in.Firewall.WGPort)
	b.WriteString("\t\ticmp type echo-request accept\n")
	b.WriteString("\t\ticmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept\n")
	if in.DropQUIC {
		fmt.Fprintf(&b, "\t\tudp dport %d drop\n", quicHTTPSPort)
	}
	b.WriteString("\t}\n\n")

	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")
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
