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
