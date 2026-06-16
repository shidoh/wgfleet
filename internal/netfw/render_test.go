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
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q:\n%s", want, out)
		}
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
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"type nat hook postrouting priority srcnat",
		`ip saddr 10.71.0.0/24 oifname != "awg0" masquerade`,
		`oifname "wgcf" tcp flags syn / syn,rst tcp option maxseg size set rt mtu`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exit egress NAT/MSS missing %q:\n%s", want, out)
		}
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

func TestRenderMasterDropsQUIC(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:     domain.RoleMaster,
		DropQUIC: true,
		Firewall: domain.FirewallSpec{WGPort: 443},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "udp dport 443 drop") {
		t.Errorf("master should drop QUIC/UDP-443:\n%s", out)
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
