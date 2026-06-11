package routing

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func argvJoin(steps []Step) string {
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(strings.Join(s.Argv, " "))
		b.WriteString("\n")
	}
	return b.String()
}

func TestRenderWARPRouting(t *testing.T) {
	steps, err := Render(domain.RoutingSpec{
		EgressInterface: "wgcf",
		DirectCIDRs:     []string{"10.0.0.0/8", "192.168.0.0/16"},
		MasterIP:        "203.0.113.1",
		FwMark:          0x1,
	})
	if err != nil {
		t.Fatal(err)
	}
	all := argvJoin(steps)

	// an earlier finding: rp_filter relaxed.
	if !strings.Contains(all, "sysctl -w net.ipv4.conf.all.rp_filter=0") {
		t.Errorf("missing rp_filter=0:\n%s", all)
	}
	// an earlier finding: conntrack flushed.
	if !strings.Contains(all, "conntrack -D") {
		t.Errorf("missing conntrack flush:\n%s", all)
	}
	// an earlier finding: master kept on main table.
	if !strings.Contains(all, "ip rule add to 203.0.113.1 lookup main") {
		t.Errorf("master not kept direct:\n%s", all)
	}
	// Direct CIDRs.
	if !strings.Contains(all, "ip rule add to 10.0.0.0/8 lookup main") {
		t.Errorf("direct cidr missing:\n%s", all)
	}
	// an earlier finding: fwmark kept on main (NOT CONNMARK).
	if !strings.Contains(all, "ip rule add fwmark 0x1 lookup main") {
		t.Errorf("fwmark rule missing:\n%s", all)
	}
	// Egress default route in the dedicated table.
	if !strings.Contains(all, "ip route replace default dev wgcf table 51820") {
		t.Errorf("egress default route missing:\n%s", all)
	}
}

func TestIpRuleDeleteThenAdd(t *testing.T) {
	steps, _ := Render(domain.RoutingSpec{
		EgressInterface: "wgcf",
		MasterIP:        "203.0.113.1",
		DirectCIDRs:     []string{"10.0.0.0/8"},
	})

	// Every `ip rule add ... pref N` must be immediately preceded by a best-effort
	// `ip rule del pref N`, so a changed selector at that pref is replaced cleanly
	// rather than leaking a duplicate across reconciles.
	for i, s := range steps {
		if len(s.Argv) >= 3 && s.Argv[0] == "ip" && s.Argv[1] == "rule" && s.Argv[2] == "add" {
			pref := s.Argv[len(s.Argv)-1]
			if i == 0 {
				t.Fatalf("add at index 0 has no preceding delete: %v", s.Argv)
			}
			del := steps[i-1]
			wantDel := []string{"ip", "rule", "del", "pref", pref}
			if strings.Join(del.Argv, " ") != strings.Join(wantDel, " ") {
				t.Errorf("add %v not preceded by `%s`, got `%s`", s.Argv,
					strings.Join(wantDel, " "), strings.Join(del.Argv, " "))
			}
			if !del.BestEffort {
				t.Errorf("delete step %v must be best-effort (rule may not exist)", del.Argv)
			}
		}
	}
}

func TestRenderDirectEgressIsNoop(t *testing.T) {
	// No egress interface ⇒ direct egress, nothing to policy-route.
	steps, err := Render(domain.RoutingSpec{DirectCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 0 {
		t.Errorf("direct egress should produce no steps, got %d", len(steps))
	}
}

func TestRenderDefaultsFwmark(t *testing.T) {
	steps, _ := Render(domain.RoutingSpec{EgressInterface: "wgcf"})
	if !strings.Contains(argvJoin(steps), "fwmark 0x1 lookup main") {
		t.Error("expected default fwmark 0x1 when unset")
	}
}
