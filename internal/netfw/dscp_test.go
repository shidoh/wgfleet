package netfw

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// scrubChainLines returns the lines of the named chain in a rendered ruleset, or nil
// when the chain is absent.
func scrubChainLines(t *testing.T, ruleset, chain string) []string {
	t.Helper()
	var body []string
	in := false
	for _, raw := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "chain "+chain+" {":
			in = true
		case in && line == "}":
			return body
		case in:
			body = append(body, line)
		}
	}
	return nil
}

func TestDSCPScrubOnExit(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:        domain.RoleExit,
		Firewall:    domain.FirewallSpec{WGPort: 51820},
		ClientCIDR:  "10.71.0.0/24",
		WGInterface: "awg0",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"type filter hook output priority mangle; policy accept;",
		`oifname != "awg0" udp sport 51820 ip dscp != cs0 ip dscp set cs0`,
		`oifname != "awg0" udp sport 51820 ip6 dscp != cs0 ip6 dscp set cs0`,
	}
	got := scrubChainLines(t, out, AWGDSCPScrubChain)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("exit DSCP scrub chain:\n got %q\nwant %q\nfull ruleset:\n%s", got, want, out)
	}
}

func TestDSCPScrubOnExitCoversTheLifeline(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:         domain.RoleExit,
		Firewall:     domain.FirewallSpec{WGPort: 51820, LifelinePort: 41827},
		ClientCIDR:   "10.71.0.0/24",
		WGInterface:  "awg0",
		LifelineCIDR: "10.99.77.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(scrubChainLines(t, out, AWGDSCPScrubChain), "\n")
	for _, want := range []string{
		`oifname != { "awg0", "awgl0" } udp sport { 41827, 51820 } ip dscp != cs0 ip dscp set cs0`,
		`oifname != { "awg0", "awgl0" } udp sport { 41827, 51820 } ip6 dscp != cs0 ip6 dscp set cs0`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lifeline exit: missing %q in\n%s", want, got)
		}
	}
}

func TestDSCPScrubOnMaster(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role:           domain.RoleMaster,
		Firewall:       domain.FirewallSpec{WGPort: 443, PublicUDPPorts: []int{9994}},
		RedirInterface: "wg0",
		RedirPort:      7895,
		ClientDNSPort:  53,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"type filter hook output priority mangle; policy accept;",
		`oifname != "wg0" udp sport 443 ip dscp != cs0 ip dscp set cs0`,
		`oifname != "wg0" udp sport 443 ip6 dscp != cs0 ip6 dscp set cs0`,
	}
	got := scrubChainLines(t, out, AWGDSCPScrubChain)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("master DSCP scrub chain:\n got %q\nwant %q", got, want)
	}
}

// Only our AmneziaWG listen ports: no other port the node opens, and nothing on
// a forwarding hook, may have its DSCP touched.
func TestDSCPScrubTouchesOnlyAWGPorts(t *testing.T) {
	out, err := RenderRuleset(RenderInput{
		Role: domain.RoleExit,
		Firewall: domain.FirewallSpec{
			WGPort:         51820,
			RealityPort:    8443,
			PublicUDPPorts: []int{9994},
			PublicTCPPorts: []int{80},
		},
		ClientCIDR: "10.71.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "dscp set"); n != 2 {
		t.Errorf("want exactly two DSCP rewrites (v4+v6), got %d:\n%s", n, out)
	}
	body := strings.Join(scrubChainLines(t, out, AWGDSCPScrubChain), "\n")
	for _, foreign := range []string{"9994", "8443", "9993", "53", "tcp"} {
		if strings.Contains(body, foreign) {
			t.Errorf("DSCP scrub matches %q, which is not an AmneziaWG port:\n%s", foreign, body)
		}
	}
	for _, hook := range []string{"forward", "postrouting", "prerouting", "input"} {
		if strings.Contains(body, "hook "+hook) {
			t.Errorf("DSCP scrub must hook output only, found %q", hook)
		}
	}
}

// The drift probe compares per-chain rule counts against the kernel; the new
// chain must count as the two rules nft will report.
func TestDSCPScrubChainCountsForDrift(t *testing.T) {
	out, err := RenderRuleset(RenderInput{Role: domain.RoleMaster, Firewall: domain.FirewallSpec{WGPort: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if n := renderedChainCounts(out)[AWGDSCPScrubChain]; n != 2 {
		t.Errorf("drift count for %s = %d, want 2", AWGDSCPScrubChain, n)
	}
}
