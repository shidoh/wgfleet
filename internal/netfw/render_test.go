package netfw

import (
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
		"10.0.0.0/33",           // bad prefix length
		"203.0.113.20; rm -rf /", // injection attempt
		"1.2.3.4 }",             // would close the nft set early
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
