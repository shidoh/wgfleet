package netfw

import (
	"fmt"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestRenderExitRuleset(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role: domain.RoleExit,
		Firewall: domain.FirewallSpec{
			ASBlacklist: true,
			Whitelist:   []string{"10.20.0.0/16", "203.0.113.20"},
			WGPort:      51820,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet wgfleet",
		"policy drop;",
		"ct state established,related accept",
		"set as_blacklist",
		"ip saddr @as_blacklist drop",
		"elements = { 10.20.0.0/16, 203.0.113.20 }",
		"tcp dport 22 accept",
		"udp dport 9993 accept",
		"udp dport 51820 accept",
		// Fail-safe: the management overlay interface is trusted wholesale so a
		// missing mgmt entry in the whitelist can never lock management out.
		`iifname "zt*" accept`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q:\n%s", want, out)
		}
	}
}

func TestRenderASBlacklistElements(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{ASBlacklist: true, WGPort: 51820},
		// Unmasked, duplicate, wrong-family and junk entries must be normalized/
		// dropped — render never trusts the cache verbatim (it runs as root).
		ASBlacklistV4: []string{"1.2.3.4/24", "1.2.3.0/24", "10.0.0.0/8", "bogus", "2001:db8::/32"},
		ASBlacklistV6: []string{"2001:db8::/32", "192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set as_blacklist {",
		"type ipv4_addr",
		// auto-merge lets the kernel fold the feeds' overlapping prefixes instead of
		// failing the whole nft load with "conflicting intervals".
		"auto-merge",
		"elements = { 1.2.3.0/24, 10.0.0.0/8 }", // masked + deduped, v6/junk excluded
		"set as_blacklist_v6 {",
		"type ipv6_addr",
		"elements = { 2001:db8::/32 }", // only the real v6 entry
		"ip saddr @as_blacklist drop",
		"ip6 saddr @as_blacklist_v6 drop",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q:\n%s", want, out)
		}
	}
	// The v4 set must not leak the IPv6 prefix, and vice versa.
	if i := strings.Index(out, "set as_blacklist {"); i >= 0 {
		v4Block := out[i:strings.Index(out, "set as_blacklist_v6")]
		if strings.Contains(v4Block, "2001:db8") {
			t.Errorf("v6 prefix leaked into the v4 set:\n%s", v4Block)
		}
	}
}

func TestRenderASBlacklistEmptyFailOpen(t *testing.T) {
	// Enabled but no cached elements yet: sets exist (so the drop rules resolve) but
	// are empty — fail-open, the WG port is not blocked before the feed is fetched.
	out, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{ASBlacklist: true, WGPort: 51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set as_blacklist {",
		"set as_blacklist_v6 {",
		"# empty: scanner feed not yet fetched (fail-open)",
		"udp dport 51820 accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "elements = {") {
		t.Errorf("expected no elements when feed unfetched:\n%s", out)
	}
}

func TestRenderTrustsMgmtOverlayWithoutWhitelist(t *testing.T) {
	// Even with an empty whitelist, the overlay interface must be accepted — this is
	// the robustness fix: a node stays reachable over ZeroTier regardless of config.
	out, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `iifname "zt*" accept`) {
		t.Errorf("overlay accept must be present even with no whitelist:\n%s", out)
	}
}

func TestRenderExitNoFlushSupersedesBaseline(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Must NOT use the global flush (would wipe master NAT / other tables on a
	// co-located node or a re-provision).
	if strings.Contains(out, "flush ruleset") {
		t.Errorf("exit firewall must not use `flush ruleset`:\n%s", out)
	}
	// Must supersede the baseline and atomically replace its own table.
	for _, want := range []string{
		"delete table inet wgfleet_baseline",
		"delete table inet wgfleet",
		"table inet wgfleet {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q:\n%s", want, out)
		}
	}
}

func TestRenderExitMangleMark(t *testing.T) {
	// With a mark + egress, the mangle rule that marks WG-server replies must appear.
	out, err := RenderRuleset(RenderInput{
		Role:        domain.RoleExit,
		Firewall:    domain.FirewallSpec{WGPort: 51820},
		WGReplyMark: 0x1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type route hook output priority mangle",
		"udp sport 51820 meta mark set 0x1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mangle mark rule missing %q:\n%s", want, out)
		}
	}
	// Without a mark (direct egress), no mangle chain.
	out2, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}})
	if strings.Contains(out2, "mangle") {
		t.Errorf("no mangle chain expected without WGReplyMark:\n%s", out2)
	}
}

func TestRenderExitEgressNAT(t *testing.T) {
	// A WARP exit MASQUERADEs client traffic on egress (else packets leave with the
	// master's private tunnel IP and the upstream drops them) and MSS-clamps TLS.
	out, err := RenderRuleset(RenderInput{
		Role:            domain.RoleExit,
		Firewall:        domain.FirewallSpec{WGPort: 51820},
		ClientCIDR:      "10.71.0.0/24",
		WGInterface:     "awg0",
		EgressInterface: "wgcf",
		ClampMSS:        1320,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type nat hook postrouting priority srcnat",
		`ip saddr 10.71.0.0/24 oifname != "awg0" masquerade`,
		// Bidirectional fixed MSS clamp (no oifname filter), not the old egress-only
		// `oifname wgcf rt mtu` which left the return path through awg0 unclamped. The
		// `> N` guard makes it a true clamp (only lowers, never raises a smaller MSS).
		`tcp flags syn / syn,rst tcp option maxseg size > 1320 tcp option maxseg size set 1320`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exit egress NAT/MSS missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "maxseg size set rt mtu") {
		t.Errorf("egress-only rt-mtu clamp must be gone (replaced by bidirectional clamp):\n%s", out)
	}
	// No ClampMSS ⇒ no forward MSS clamp.
	out0, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}, ClientCIDR: "10.71.0.0/24", WGInterface: "awg0", EgressInterface: "wgcf"})
	if strings.Contains(out0, "maxseg") {
		t.Errorf("no MSS clamp expected when ClampMSS is 0:\n%s", out0)
	}

	// No client pool ⇒ no masquerade chain (fail-safe; never SNAT blindly).
	out2, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}})
	if strings.Contains(out2, "masquerade") {
		t.Errorf("no masquerade expected without ClientCIDR:\n%s", out2)
	}
	// A master never gets the exit masquerade here (it has its own NAT table).
	out3, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}, ClientCIDR: "10.73.0.0/24"})
	if strings.Contains(out3, "masquerade") {
		t.Errorf("master ruleset must not carry the exit masquerade:\n%s", out3)
	}
}

func TestRenderForwardDropsInvalid(t *testing.T) {
	// Transit packets conntrack cannot place must be dropped, NOT forwarded. An
	// INVALID packet carries no NAT binding, so forwarding it lets a client-pool
	// source escape the egress un-masqueraded — which poisons the upstream return
	// path and ends in mid-stream resets (traced live 2026-07-27). The rule belongs
	// to the forward chain specifically: input already had it, and an exit forwards.
	for _, role := range []domain.Role{domain.RoleExit, domain.RoleMaster} {
		out, err := RenderRuleset(RenderInput{
			Role:       role,
			Firewall:   domain.FirewallSpec{WGPort: 51820},
			ClientCIDR: "10.71.0.0/24",
		})
		if err != nil {
			t.Fatalf("role %v: %v", role, err)
		}
		forward, ok := chainBody(out, "chain forward")
		if !ok {
			t.Fatalf("role %v: no forward chain rendered:\n%s", role, out)
		}
		if !strings.Contains(forward, "ct state invalid drop") {
			t.Errorf("role %v: forward chain must drop invalid:\n%s", role, forward)
		}
	}
}

func TestRenderExitEgressLeakGuard(t *testing.T) {
	// The guard asserts what the masquerade promises: no client-pool source may reach
	// the wire. It must sit AFTER srcnat (so translated packets no longer match) and
	// mirror the masquerade's scope exactly, or it would either fire on legitimate
	// traffic or miss the leak it exists to catch.
	out, err := RenderRuleset(RenderInput{
		Role:            domain.RoleExit,
		Firewall:        domain.FirewallSpec{WGPort: 51820},
		ClientCIDR:      "10.71.0.0/24",
		WGInterface:     "awg0",
		EgressInterface: "wgcf",
	})
	if err != nil {
		t.Fatal(err)
	}
	guard, ok := chainBody(out, "chain egress_leak_guard")
	if !ok {
		t.Fatalf("exit must render an egress leak guard:\n%s", out)
	}
	for _, want := range []string{
		// After srcnat: a packet still carrying the pool here is one NAT never saw.
		"type filter hook postrouting priority srcnat + 10",
		// Same pool and same interface scope as the masquerade it backs up, minus
		// the two cases that are the node itself rather than a client: loopback is
		// not egress at all, and the gateway address inside the pool belongs to the
		// node. Counting those made a healthy exit report half a million leaks.
		`ip saddr 10.71.0.0/24 ip saddr != 10.71.0.1 oifname != "awg0" oifname != "lo" counter drop`,
	} {
		if !strings.Contains(guard, want) {
			t.Errorf("egress leak guard missing %q:\n%s", want, guard)
		}
	}

	// No client pool ⇒ nothing to guard (and no pool literal to render).
	out2, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}})
	if strings.Contains(out2, "egress_leak_guard") {
		t.Errorf("no guard expected without ClientCIDR:\n%s", out2)
	}
	// A master SNATs in its own table; this guard is the exit's.
	out3, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}, ClientCIDR: "10.73.0.0/24"})
	if strings.Contains(out3, "egress_leak_guard") {
		t.Errorf("master must not carry the exit egress guard:\n%s", out3)
	}
}

func TestRenderExitLifelinePool(t *testing.T) {
	// A lifeline (the reserve client-facing AWG interface, domain.LifelineInterface
	// == "awgl0") gets the same treatment as the primary client pool: its UDP port
	// accepted on input, its pool masqueraded on egress and guarded against leaks —
	// scoped to its own interface, alongside (not instead of) the primary pool's.
	out, err := RenderRuleset(RenderInput{
		Role:              domain.RoleExit,
		Firewall:          domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
		ClientCIDR:        "10.90.0.0/24",
		WGInterface:       "awg0",
		LifelineCIDR:      "10.98.77.0/24",
		LifelineInterface: "awgl0",
		EgressInterface:   "wgcf",
		WGReplyMark:       0x1,
	})
	if err != nil {
		t.Fatal(err)
	}
	input, ok := chainBody(out, "chain input")
	if !ok {
		t.Fatalf("no input chain rendered:\n%s", out)
	}
	if !strings.Contains(input, "udp dport 41827 accept") {
		t.Errorf("input chain missing lifeline port accept:\n%s", input)
	}

	postrouting, ok := chainBody(out, "chain postrouting")
	if !ok {
		t.Fatalf("no postrouting chain rendered:\n%s", out)
	}
	for _, want := range []string{
		`ip saddr 10.90.0.0/24 oifname != "awg0" masquerade`,
		`ip saddr 10.98.77.0/24 oifname != "awgl0" masquerade`,
	} {
		if !strings.Contains(postrouting, want) {
			t.Errorf("postrouting chain missing %q:\n%s", want, postrouting)
		}
	}

	guard, ok := chainBody(out, "chain egress_leak_guard")
	if !ok {
		t.Fatalf("no egress leak guard rendered:\n%s", out)
	}
	for _, want := range []string{
		`ip saddr 10.90.0.0/24 ip saddr != 10.90.0.1 oifname != "awg0" oifname != "lo" counter drop`,
		`ip saddr 10.98.77.0/24 ip saddr != 10.98.77.1 oifname != "awgl0" oifname != "lo" counter drop`,
	} {
		if !strings.Contains(guard, want) {
			t.Errorf("egress leak guard missing %q:\n%s", want, guard)
		}
	}

	if !strings.Contains(out, "udp sport { 51820, 41827 } meta mark set 0x1") {
		t.Errorf("mangle mark rule must cover both wg and lifeline ports as a set:\n%s", out)
	}
}

func TestRenderExitLifelineInterfaceDefault(t *testing.T) {
	// LifelineInterface empty ⇒ defaults to domain.LifelineInterface ("awgl0"),
	// mirroring WGInterface's own default-to-"awg0" behaviour.
	out, err := RenderRuleset(RenderInput{
		Role:         domain.RoleExit,
		Firewall:     domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
		LifelineCIDR: "10.98.77.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `ip saddr 10.98.77.0/24 oifname != "awgl0" masquerade`) {
		t.Errorf("lifeline masquerade must default to awgl0:\n%s", out)
	}
}

func TestRenderExitNoLifelineIsByteIdentical(t *testing.T) {
	// Without a lifeline, the render must be completely unaffected: no lifeline port
	// accept, no second masquerade/guard rule, and the mangle rule keeps its
	// original single-port form (not a one-element set).
	withLifelineFieldsZero, err := RenderRuleset(RenderInput{
		Role:            domain.RoleExit,
		Firewall:        domain.FirewallSpec{WGPort: 51820},
		ClientCIDR:      "10.71.0.0/24",
		WGInterface:     "awg0",
		EgressInterface: "wgcf",
		WGReplyMark:     0x1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withLifelineFieldsZero, "41827") || strings.Contains(withLifelineFieldsZero, "awgl0") {
		t.Errorf("no lifeline fields set: ruleset must carry nothing lifeline-related:\n%s", withLifelineFieldsZero)
	}
	if !strings.Contains(withLifelineFieldsZero, "udp sport 51820 meta mark set 0x1") {
		t.Errorf("mangle rule must keep its single-port form without a lifeline:\n%s", withLifelineFieldsZero)
	}
	if strings.Contains(withLifelineFieldsZero, "udp sport {") {
		t.Errorf("mangle rule must not render a set without a lifeline:\n%s", withLifelineFieldsZero)
	}
}

func TestRenderExitLifelinePortWithoutCIDRIsAnError(t *testing.T) {
	// A hole with no listener behind it must not render silently.
	_, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
	})
	if err == nil {
		t.Fatal("expected an error when LifelinePort is set without LifelineCIDR")
	}
}

func TestRenderExitLifelineCIDRWithoutPortIsAnError(t *testing.T) {
	// A listener with no hole opened for it must not render silently.
	_, err := RenderRuleset(RenderInput{
		Role:         domain.RoleExit,
		Firewall:     domain.FirewallSpec{WGPort: 51820},
		LifelineCIDR: "10.98.77.0/24",
	})
	if err == nil {
		t.Fatal("expected an error when LifelineCIDR is set without Firewall.LifelinePort")
	}
}

// chainBody returns the text of a rendered chain, from its header to the closing
// brace. Assertions scoped to one chain cannot be satisfied by a matching rule that
// happens to live in a different chain.
func chainBody(ruleset, header string) (string, bool) {
	start := strings.Index(ruleset, header)
	if start < 0 {
		return "", false
	}
	body, _, ok := strings.Cut(ruleset[start:], "\n\t}")
	if !ok {
		return "", false
	}
	return body, true
}

func TestRenderOverlayMSSClamp(t *testing.T) {
	// With OverlayMSS set, a postrouting MSS clamp on the overlay interface appears
	// (control-plane insurance against a too-large ZeroTier MTU).
	out, err := RenderRuleset(RenderInput{
		Role:       domain.RoleExit,
		Firewall:   domain.FirewallSpec{WGPort: 51820},
		OverlayMSS: 1240,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type filter hook postrouting priority mangle",
		`oifname "zt*" tcp flags syn / syn,rst tcp option maxseg size > 1240 tcp option maxseg size set 1240`,
		// Paired rule for traffic ARRIVING over the overlay and leaving elsewhere
		// (master forwarding a client's flow to a host behind a ZeroTier member).
		// Without it only the far host is bounded: the near side's SYN-ACK keeps
		// whatever MSS the client-facing clamp wrote (1320 on the master) and the
		// CLIENT then sends 1320-byte segments into a 1280-byte overlay. Small
		// requests pass, the first full-size upload black-holes.
		`iifname "zt*" tcp flags syn / syn,rst tcp option maxseg size > 1240 tcp option maxseg size set 1240`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("overlay MSS clamp missing %q:\n%s", want, out)
		}
	}

	// Disabled (0) ⇒ no clamp.
	out2, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}})
	if strings.Contains(out2, "maxseg size set 1240") {
		t.Errorf("no overlay clamp expected when OverlayMSS is 0:\n%s", out2)
	}
}

func TestRenderMasterInputFirewall(t *testing.T) {
	// The master reuses RenderRuleset for its input filter: drop policy, overlay +
	// SSH + client WG port open, NO masquerade (that is the exit's; the master NATs
	// in a separate table) and NO QUIC drop in the input chain (client QUIC is
	// dropped at the NAT prerouting layer, see master_nat.go).
	out, err := RenderRuleset(RenderInput{
		Role:     domain.RoleMaster,
		Firewall: domain.FirewallSpec{WGPort: 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet wgfleet",
		"policy drop;",
		`iifname "zt*" accept`,
		"tcp dport 22 accept",
		"udp dport 443 accept", // client AWG listener
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master input firewall missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "udp dport 443 drop") {
		t.Errorf("master input chain must not drop its own WG/client port:\n%s", out)
	}
	if strings.Contains(out, "masquerade") {
		t.Errorf("master input firewall must not carry the exit masquerade:\n%s", out)
	}
}

func TestRenderMasterAcceptsRedirPort(t *testing.T) {
	// Client TCP is DNAT'd to the local mihomo redir port and lands on the INPUT
	// hook; with the drop policy the redirected SYN must be explicitly accepted, or
	// clients get pings/DNS but no web. The accept is scoped to the client interface.
	out, err := RenderRuleset(RenderInput{
		Role:           domain.RoleMaster,
		Firewall:       domain.FirewallSpec{WGPort: 443},
		RedirPort:      7895,
		RedirInterface: "wg0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `iifname "wg0" tcp dport 7895 accept`; !strings.Contains(out, want) {
		t.Errorf("master input firewall missing redir accept %q:\n%s", want, out)
	}

	// Default interface when unset.
	out2, _ := RenderRuleset(RenderInput{
		Role:      domain.RoleMaster,
		Firewall:  domain.FirewallSpec{WGPort: 443},
		RedirPort: 7895,
	})
	if want := `iifname "wg0" tcp dport 7895 accept`; !strings.Contains(out2, want) {
		t.Errorf("master input firewall missing default-interface redir accept %q:\n%s", want, out2)
	}

	// Exit role and zero port never emit the redirect accept.
	out3, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}})
	if strings.Contains(out3, "dport 7895") {
		t.Errorf("no redir accept expected when RedirPort is zero:\n%s", out3)
	}
	out4, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}, RedirPort: 7895})
	if strings.Contains(out4, "dport 7895") {
		t.Errorf("redir accept is master-only, must not appear on exit:\n%s", out4)
	}
}

func TestRenderMasterAcceptsClientDNSPort(t *testing.T) {
	// Master-tier blocky (ADR-0024): clients query the master gateway for DNS, which
	// lands on INPUT. Open it UDP+TCP, scoped to the client interface, when set.
	out, err := RenderRuleset(RenderInput{
		Role:           domain.RoleMaster,
		Firewall:       domain.FirewallSpec{WGPort: 443},
		RedirInterface: "wg0",
		ClientDNSPort:  53,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "wg0" udp dport 53 accept`,
		`iifname "wg0" tcp dport 53 accept`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master input firewall missing client DNS accept %q:\n%s", want, out)
		}
	}

	// Zero port never opens DNS (clients use another resolver).
	out2, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}})
	if strings.Contains(out2, "dport 53 accept") {
		t.Errorf("no client DNS accept expected when ClientDNSPort is zero:\n%s", out2)
	}
	// Exit role never emits the client DNS accept (master-only).
	out3, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}, ClientDNSPort: 53})
	if strings.Contains(out3, "dport 53 accept") {
		t.Errorf("client DNS accept is master-only, must not appear on exit:\n%s", out3)
	}
}

func TestRenderMasterClientMSSClamp(t *testing.T) {
	// The master clamps client-facing TCP MSS to the true client-path MTU so large
	// server→client segments (SSH KEX, dashboard HTML, sustained downloads) do not
	// black-hole on the tight client tunnel while pings/DNS survive.
	out, err := RenderRuleset(RenderInput{
		Role:           domain.RoleMaster,
		Firewall:       domain.FirewallSpec{WGPort: 443},
		RedirInterface: "wg0",
		ClientMSS:      1280,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both directions across the client interface must be clamped: incoming SYN
	// (bounds master→client) and outgoing SYN-ACK (bounds client→master). The `> N`
	// guard makes it a true clamp — it must never raise a client's smaller MSS.
	for _, want := range []string{
		`iifname "wg0" tcp flags syn / syn,rst tcp option maxseg size > 1280 tcp option maxseg size set 1280`,
		`oifname "wg0" tcp flags syn / syn,rst tcp option maxseg size > 1280 tcp option maxseg size set 1280`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master missing client MSS clamp %q:\n%s", want, out)
		}
	}

	// Default interface when RedirInterface is unset.
	out2, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}, ClientMSS: 1280})
	if want := `iifname "wg0" tcp flags syn / syn,rst tcp option maxseg size > 1280 tcp option maxseg size set 1280`; !strings.Contains(out2, want) {
		t.Errorf("master missing default-interface client MSS clamp %q:\n%s", want, out2)
	}

	// Zero ⇒ no clamp; exit role never emits it (master-only).
	out3, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}})
	if strings.Contains(out3, "chain client_mss") {
		t.Errorf("no client MSS clamp expected when ClientMSS is zero:\n%s", out3)
	}
	out4, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}, ClientMSS: 1280})
	if strings.Contains(out4, "chain client_mss") {
		t.Errorf("client MSS clamp is master-only, must not appear on exit:\n%s", out4)
	}
}

func TestRenderMasterAcceptsClientAdminPorts(t *testing.T) {
	// Opt-in: admin UIs (controller Web UI, mihomo dashboard) bound to the mgmt
	// overlay must be reachable by the client pool, so the master input chain accepts
	// client-interface TCP to those ports. Scoped to the client interface.
	out, err := RenderRuleset(RenderInput{
		Role:             domain.RoleMaster,
		Firewall:         domain.FirewallSpec{WGPort: 443},
		RedirInterface:   "wg0",
		ClientAdminPorts: []int{9000, 9090},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "wg0" tcp dport 9000 accept`,
		`iifname "wg0" tcp dport 9090 accept`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master input firewall missing admin-port accept %q:\n%s", want, out)
		}
	}

	// Default interface when RedirInterface is unset.
	out2, _ := RenderRuleset(RenderInput{
		Role:             domain.RoleMaster,
		Firewall:         domain.FirewallSpec{WGPort: 443},
		ClientAdminPorts: []int{9000},
	})
	if want := `iifname "wg0" tcp dport 9000 accept`; !strings.Contains(out2, want) {
		t.Errorf("master input firewall missing default-interface admin accept %q:\n%s", want, out2)
	}

	// Out-of-range ports are skipped, not emitted.
	out3, _ := RenderRuleset(RenderInput{
		Role:             domain.RoleMaster,
		Firewall:         domain.FirewallSpec{WGPort: 443},
		ClientAdminPorts: []int{0, 70000, 9090},
	})
	if strings.Contains(out3, "dport 0 ") || strings.Contains(out3, "dport 70000") {
		t.Errorf("invalid admin ports must be skipped:\n%s", out3)
	}

	// Default (no admin ports) keeps the strict posture: no extra accepts.
	out4, _ := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}})
	if strings.Contains(out4, "dport 9000") || strings.Contains(out4, "dport 9090") {
		t.Errorf("no admin-port accept expected by default:\n%s", out4)
	}

	// Exit role never emits the admin accepts (master-only).
	out5, _ := RenderRuleset(RenderInput{Role: domain.RoleExit, Firewall: domain.FirewallSpec{WGPort: 51820}, ClientAdminPorts: []int{9000}})
	if strings.Contains(out5, "dport 9000") {
		t.Errorf("admin accept is master-only, must not appear on exit:\n%s", out5)
	}
}

func TestRenderWithoutBlacklist(t *testing.T) {
	out, err := RenderRuleset(RenderInput{Firewall: domain.FirewallSpec{WGPort: 51820}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "as_blacklist") {
		t.Errorf("blacklist set should be absent when disabled:\n%s", out)
	}
}

func TestRenderRejectsBadPort(t *testing.T) {
	if _, err := RenderRuleset(RenderInput{Firewall: domain.FirewallSpec{WGPort: 0}}); err == nil {
		t.Fatal("expected error for missing WG port")
	}
}

func TestRenderRejectsBadWhitelistEntry(t *testing.T) {
	for _, bad := range []string{
		"not-an-ip",
		"10.0.0.0/33",            // bad prefix length
		"203.0.113.20; rm -rf /", // injection attempt
		"1.2.3.4 }",              // would close the nft set early
	} {
		_, err := RenderRuleset(RenderInput{
			Role:     domain.RoleExit,
			Firewall: domain.FirewallSpec{Whitelist: []string{bad}, WGPort: 51820},
		})
		if err == nil {
			t.Errorf("expected error for whitelist entry %q", bad)
		}
	}
}

func TestRenderCanonicalizesWhitelist(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role: domain.RoleExit,
		Firewall: domain.FirewallSpec{
			// Host bits set + surrounding whitespace; both must be normalized.
			Whitelist: []string{" 10.5.6.7/24 ", "2001:db8::1"}, // IPv6 parsed then skipped
			WGPort:    51820,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "elements = { 10.5.6.0/24 }") {
		t.Errorf("whitelist not canonicalized (want masked 10.5.6.0/24, IPv6 skipped):\n%s", out)
	}
}

// Public TCP ports are world-facing (no iifname scope) and role-agnostic: the
// same knob opens the master's decoy web listener and, on an exit, any other
// publicly reachable TCP service. Contrast ClientAdminPorts, which is scoped to
// the client interface and master-only.
func TestRenderRulesetPublicTCPPorts(t *testing.T) {
	for _, role := range []domain.Role{domain.RoleMaster, domain.RoleExit} {
		t.Run(string(role), func(t *testing.T) {
			out, err := RenderRuleset(RenderInput{
				Role: role,
				Firewall: domain.FirewallSpec{
					WGPort: 51820,
					// Unsorted, duplicated and out-of-range entries on purpose: the
					// renderer must normalise so the rendered file is stable across
					// passes (an unstable render would re-apply the ruleset forever).
					PublicTCPPorts: []int{443, 80, 443, 0, 70000, -1},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"tcp dport 80 accept\n",
				"tcp dport 443 accept\n",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("ruleset missing %q:\n%s", want, out)
				}
			}
			if n := strings.Count(out, "tcp dport 443 accept"); n != 1 {
				t.Errorf("port 443 rendered %d times, want 1 (dedupe):\n%s", n, out)
			}
			for _, bad := range []string{"tcp dport 0 accept", "tcp dport 70000 accept", "tcp dport -1 accept"} {
				if strings.Contains(out, bad) {
					t.Errorf("ruleset should not contain out-of-range rule %q:\n%s", bad, out)
				}
			}
			// Ascending order keeps the render deterministic regardless of manifest order.
			if i, j := strings.Index(out, "tcp dport 80 accept"), strings.Index(out, "tcp dport 443 accept"); i > j {
				t.Errorf("ports not rendered in ascending order:\n%s", out)
			}
			// World-facing: must NOT be scoped to an interface.
			if strings.Contains(out, `iifname "wg0" tcp dport 443`) {
				t.Errorf("public port must not be interface-scoped:\n%s", out)
			}
		})
	}
}

// An empty/absent list must render nothing at all — no stray rules, and no
// difference from a manifest that never mentioned the knob.
func TestRenderRulesetPublicTCPPortsEmpty(t *testing.T) {
	with, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820, PublicTCPPorts: []int{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	without, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	if with != without {
		t.Errorf("empty public_tcp_ports changed the render:\n--- with ---\n%s\n--- without ---\n%s", with, without)
	}
}

func TestRenderRulesetPublicUDPPorts(t *testing.T) {
	for _, role := range []domain.Role{domain.RoleMaster, domain.RoleExit} {
		t.Run(string(role), func(t *testing.T) {
			out, err := RenderRuleset(RenderInput{
				Role: role,
				Firewall: domain.FirewallSpec{
					WGPort: 51820,
					// Unsorted, with duplicates and out-of-range values on purpose:
					// the render must normalise them, otherwise the file changes
					// every pass and the firewall is re-applied forever.
					PublicUDPPorts: []int{9994, 500, 9994, 0, 70000, -1},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"udp dport 500 accept\n",
				"udp dport 9994 accept\n",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("ruleset missing %q:\n%s", want, out)
				}
			}
			if n := strings.Count(out, "udp dport 9994 accept"); n != 1 {
				t.Errorf("port 9994 rendered %d times, want 1 (dedupe):\n%s", n, out)
			}
			for _, bad := range []string{"udp dport 0 accept", "udp dport 70000 accept", "udp dport -1 accept"} {
				if strings.Contains(out, bad) {
					t.Errorf("ruleset should not contain out-of-range rule %q:\n%s", bad, out)
				}
			}
			if i, j := strings.Index(out, "udp dport 500 accept"), strings.Index(out, "udp dport 9994 accept"); i > j {
				t.Errorf("ports not rendered in ascending order:\n%s", out)
			}
			if strings.Contains(out, `iifname "wg0" udp dport 9994`) {
				t.Errorf("public port must not be interface-scoped:\n%s", out)
			}
		})
	}
}

// An empty or missing list must not change the render at all.
func TestRenderRulesetPublicUDPPortsEmpty(t *testing.T) {
	with, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820, PublicUDPPorts: []int{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	without, err := RenderRuleset(RenderInput{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820},
	})
	if err != nil {
		t.Fatal(err)
	}
	if with != without {
		t.Errorf("empty PublicUDPPorts changed the ruleset:\n--- with ---\n%s\n--- without ---\n%s", with, without)
	}
}

// The render must be byte-for-byte stable regardless of manifest order,
// otherwise FileAction sees a change and re-applies nft on every pass.
func TestRenderRulesetPublicUDPPortsStable(t *testing.T) {
	a, err := RenderRuleset(RenderInput{
		Role:     domain.RoleMaster,
		Firewall: domain.FirewallSpec{WGPort: 51820, PublicUDPPorts: []int{9994, 500}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderRuleset(RenderInput{
		Role:     domain.RoleMaster,
		Firewall: domain.FirewallSpec{WGPort: 51820, PublicUDPPorts: []int{500, 9994}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("manifest order changed the rendered ruleset:\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
}

// A TPROXY'd packet still traverses INPUT, and it does so with the destination
// the CLIENT chose — tproxy hands it to a transparent socket without rewriting
// anything. So an accept keyed on the tproxy port would never match, and the
// master's drop policy would swallow every intercepted datagram: client UDP
// silently dead, exactly the shape of an earlier finding (pings and DNS fine, the
// redirected protocol gone). The mark the tproxy chain set is the only thing that
// identifies these packets, so the accept has to key on that.
func TestMasterInputAcceptsTProxyMarkedPackets(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:           domain.RoleMaster,
		Firewall:       domain.FirewallSpec{WGPort: 443},
		RedirPort:      7895,
		RedirInterface: "wg0",
		TProxyMark:     TProxyMark,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	input, ok := chainBody(out, "chain input")
	if !ok {
		t.Fatalf("no input chain:\n%s", out)
	}
	// Scoped: an unscoped `meta mark 0x2 accept` is an unconditional hole in a drop
	// policy, and the mark is not a capability — anything on the box able to set it
	// walks through. UDP, on the client interface, which is the only shape a
	// successfully intercepted client datagram can have.
	want := fmt.Sprintf("iifname %q meta l4proto udp meta mark %#x accept", "wg0", TProxyMark)
	if !strings.Contains(input, want) {
		t.Errorf("input chain never accepts %q; every intercepted client datagram is dropped:\n%s", want, input)
	}
}

// And without interception configured the rule must not appear — an accept for a
// mark nothing sets is a rule that can only ever surprise the next reader.
func TestMasterInputHasNoTProxyAcceptWhenUnused(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:           domain.RoleMaster,
		Firewall:       domain.FirewallSpec{WGPort: 443},
		RedirPort:      7895,
		RedirInterface: "wg0",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "meta mark") {
		t.Errorf("rendered a mark-based accept with no interception configured:\n%s", out)
	}
}

// A drop-policy input chain with nothing accepting the veth isolates mihomo's
// namespace from this host: no fleet resolver. It also broke the readiness gate
// itself — `nsenter --net` changes only the network namespace, so `getent` inside
// still reads the HOST's resolv.conf, sends the query to the gateway, and had it
// dropped right here.
//
// What it must NOT do is trust the interface wholesale. The rule at pref 400 routes
// client traffic into that namespace, and whatever it forwards back arrives here on
// this interface: a bare accept offers every client a path to sshd, to the
// controller's API and web panel, and to ztnet.
func TestInputChainOpensTheResolverToTheNamespaceAndNothingElse(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Firewall:       domain.FirewallSpec{WGPort: 51820},
		Role:           domain.RoleMaster,
		NetnsHostIface: "mih-host",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		`iifname "mih-host" udp dport 53 accept`,
		`iifname "mih-host" tcp dport 53 accept`,
		// DNS-over-TLS: REALITY clients' app DNS engines dial blocky over DoT (:853),
		// measured on the wire 2026-09-06 (every client DNS flow on :853, none on :53),
		// so admitting only :53 black-holes them.
		`iifname "mih-host" tcp dport 853 accept`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the namespace cannot reach the fleet resolver; missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `iifname "mih-host" accept`) {
		t.Errorf("the veth is trusted wholesale, so a client can reach this host's own services through it:\n%s", out)
	}
}

// And before the move there is no veth to trust, so nothing is opened.
func TestInputChainOpensNothingBeforeTheMove(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Firewall: domain.FirewallSpec{WGPort: 51820},
		Role:     domain.RoleMaster,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "mih-host") {
		t.Errorf("an unmoved master trusts an interface that does not exist:\n%s", out)
	}
}

func TestRenderExitLifelineResolverPorts(t *testing.T) {
	// Reserve clients are handed the lifeline gateway as their resolver, and the
	// exit's own blocky binds it — so their DNS lands on THIS node's INPUT hook and
	// the drop policy eats it unless the resolver ports are let in, scoped to the
	// lifeline interface. :853 as well: clients resolve over DoT regardless of the
	// bare-IP nameserver they were handed.
	out, err := RenderRuleset(RenderInput{
		Role:            domain.RoleExit,
		Firewall:        domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
		LifelineCIDR:    "10.98.77.0/24",
		LifelineDNSPort: 53,
		LifelineDoTPort: 853,
	})
	if err != nil {
		t.Fatal(err)
	}
	input, ok := chainBody(out, "chain input")
	if !ok {
		t.Fatalf("no input chain rendered:\n%s", out)
	}
	for _, want := range []string{
		`iifname "awgl0" udp dport 53 accept`,
		`iifname "awgl0" tcp dport 53 accept`,
		`iifname "awgl0" tcp dport 853 accept`,
	} {
		if !strings.Contains(input, want) {
			t.Errorf("input chain missing %q:\n%s", want, input)
		}
	}
}

func TestRenderExitLifelineResolverPortsFollowTheInterfaceOverride(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:              domain.RoleExit,
		Firewall:          domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
		LifelineCIDR:      "10.98.77.0/24",
		LifelineInterface: "awgl9",
		LifelineDNSPort:   53,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `iifname "awgl9" udp dport 53 accept`) {
		t.Errorf("resolver accept must use the named lifeline interface:\n%s", out)
	}
}

func TestRenderExitLifelineWithoutResolverPortsOpensNothing(t *testing.T) {
	// The exit runs no resolver (dns disabled): a lifeline alone must not open :53.
	out, err := RenderRuleset(RenderInput{
		Role:         domain.RoleExit,
		Firewall:     domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
		LifelineCIDR: "10.98.77.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"dport 53 accept", "dport 853 accept"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("no resolver ports set: ruleset must not carry %q:\n%s", unwanted, out)
		}
	}
}

func TestRenderExitResolverPortsWithoutALifelineOpenNothing(t *testing.T) {
	// The ports are meaningless without a pool to serve; they must never render an
	// unscoped or lifeline-named accept on an exit that carries no reserve leg.
	out, err := RenderRuleset(RenderInput{
		Role:            domain.RoleExit,
		Firewall:        domain.FirewallSpec{WGPort: 51820},
		ClientCIDR:      "10.71.0.0/24",
		LifelineDNSPort: 53,
		LifelineDoTPort: 853,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "awgl0") || strings.Contains(out, "dport 53 accept") || strings.Contains(out, "dport 853 accept") {
		t.Errorf("no lifeline: ruleset must carry no resolver accepts:\n%s", out)
	}
}
