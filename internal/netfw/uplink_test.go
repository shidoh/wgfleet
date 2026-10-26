package netfw

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func uplinkInput(role domain.Role, addr string) RenderInput {
	in := RenderInput{Role: role, Firewall: domain.FirewallSpec{WGPort: 443}}
	if addr != "" {
		in.UplinkAddr = netip.MustParseAddr(addr)
	}
	return in
}

func TestMasterRendersUplinkHandshakeCounters(t *testing.T) {
	out, err := RenderRuleset(uplinkInput(domain.RoleMaster, "192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"counter uplink_syn_out {",
		"counter uplink_synack_in {",
		`ip saddr 192.0.2.10 tcp flags & (syn | ack) == syn counter name "uplink_syn_out"`,
		`ip daddr 192.0.2.10 tcp flags & (syn | ack) == (syn | ack) counter name "uplink_synack_in"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, out)
		}
	}
}

// The SYN is counted after source NAT, when a SYN mihomo's namespace sent already
// carries the host's address; the SYN-ACK before destination NAT, while it still
// does. The other way round, every forwarded handshake is invisible.
func TestUplinkCountersSitOutsideTheNATHooks(t *testing.T) {
	out, err := RenderRuleset(uplinkInput(domain.RoleMaster, "192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	for chain, hook := range map[string]string{
		"uplink_syn_out":   "type filter hook postrouting priority srcnat + 50;",
		"uplink_synack_in": "type filter hook prerouting priority dstnat - 50;",
	} {
		i := strings.Index(out, "chain "+chain+" {")
		if i < 0 {
			t.Fatalf("no chain %s", chain)
		}
		block := out[i:]
		if end := strings.Index(block, "}"); end >= 0 {
			block = block[:end]
		}
		if !strings.Contains(block, hook) {
			t.Errorf("chain %s is not on %q:\n%s", chain, hook, block)
		}
	}
}

func TestNoUplinkCountersWithoutAnAddressOffAMasterOrForIPv6(t *testing.T) {
	for name, in := range map[string]RenderInput{
		"master, no address": uplinkInput(domain.RoleMaster, ""),
		"exit":               uplinkInput(domain.RoleExit, "192.0.2.10"),
		"master, IPv6":       uplinkInput(domain.RoleMaster, "2001:db8::1"),
	} {
		out, err := RenderRuleset(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(out, "uplink_") {
			t.Errorf("%s: rendered uplink counters:\n%s", name, out)
		}
	}
}

// The counters must not cost the drift probe its accuracy: one rule per chain,
// counted the way the kernel counts them, and the counter declarations counted as
// nothing. A miscount here re-applies the firewall every pass forever.
func TestUplinkCountersKeepDriftCountsExact(t *testing.T) {
	out, err := RenderRuleset(uplinkInput(domain.RoleMaster, "192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	counts := renderedChainCounts(out)
	for _, chain := range []string{"uplink_syn_out", "uplink_synack_in"} {
		if counts[chain] != 1 {
			t.Errorf("chain %s counted %d rules, want 1", chain, counts[chain])
		}
	}
	if _, ok := counts["uplink_syn_out {"]; ok {
		t.Error("a counter declaration was counted as a chain")
	}
}
