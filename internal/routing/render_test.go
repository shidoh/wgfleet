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
		ClientCIDR:      "10.81.0.0/24",
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
	// an earlier finding: the egress rule MUST be scoped to the client source subnet, never
	// `from all` — else the host's own traffic is pulled into WARP and the node is
	// cut off when WARP is down.
	if !strings.Contains(all, "ip rule add from 10.81.0.0/24 lookup 51820") {
		t.Errorf("egress rule not scoped to client subnet:\n%s", all)
	}
	if strings.Contains(all, "ip rule add lookup 51820") {
		t.Errorf("egress rule is `from all` (no source scope) — would cut the host off WARP:\n%s", all)
	}
}

// TestRenderNoClientCIDROmitsEgress: with no client source subnet, Render must
// NOT emit the egress rule/route at all (it must never fall back to `from all`).
func TestRenderNoClientCIDROmitsEgress(t *testing.T) {
	steps, err := Render(domain.RoutingSpec{EgressInterface: "wgcf", MasterIP: "203.0.113.1"})
	if err != nil {
		t.Fatal(err)
	}
	all := argvJoin(steps)
	if strings.Contains(all, "lookup 51820") || strings.Contains(all, "table 51820") {
		t.Errorf("no ClientCIDR ⇒ no egress rule/route, got:\n%s", all)
	}
	// The host-direct safety rules (master/fwmark) must still be present.
	if !strings.Contains(all, "fwmark 0x1 lookup main") {
		t.Errorf("safety rules missing:\n%s", all)
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

func TestRenderRejectsTooManyDirectCIDRs(t *testing.T) {
	over := make([]string, MaxDirectCIDRs+1)
	for i := range over {
		over[i] = "10.0.0.0/8"
	}
	_, err := Render(domain.RoutingSpec{EgressInterface: "wgcf", DirectCIDRs: over})
	if err == nil {
		t.Fatal("expected error when direct CIDRs exceed the cap (would collide with fwmark rule)")
	}

	// The last direct-CIDR priority must stay strictly below the fwmark priority.
	steps, err := Render(domain.RoutingSpec{
		EgressInterface: "wgcf",
		DirectCIDRs:     over[:MaxDirectCIDRs],
	})
	if err != nil {
		t.Fatalf("at the cap should render: %v", err)
	}
	if !strings.Contains(argvJoin(steps), "fwmark") {
		t.Error("fwmark rule missing at the cap")
	}
}

func TestRenderDefaultsFwmark(t *testing.T) {
	steps, _ := Render(domain.RoutingSpec{EgressInterface: "wgcf"})
	if !strings.Contains(argvJoin(steps), "fwmark 0x1 lookup main") {
		t.Error("expected default fwmark 0x1 when unset")
	}
}

func TestManagedPrefsMatchRenderedRules(t *testing.T) {
	spec := domain.RoutingSpec{
		EgressInterface: "wgcf",
		MasterIP:        "203.0.113.1",
		DirectCIDRs:     []string{"10.0.0.0/8", "192.168.0.0/16"},
		ClientCIDR:      "10.81.0.0/24",
	}
	prefs := ManagedPrefs(spec)
	// master + 2 direct CIDRs + fwmark + egress = 5 priorities.
	if len(prefs) != 5 {
		t.Fatalf("expected 5 managed prefs, got %d (%v)", len(prefs), prefs)
	}
	want := []int{prefMaster, prefDirect0, prefDirect0 + 1, prefFwmark, prefEgress}
	for i, p := range want {
		if prefs[i] != p {
			t.Errorf("pref[%d] = %d, want %d", i, prefs[i], p)
		}
	}
	// Direct-egress spec installs nothing.
	if got := ManagedPrefs(domain.RoutingSpec{}); got != nil {
		t.Errorf("direct egress should manage no prefs, got %v", got)
	}
}

func TestKernelReflects(t *testing.T) {
	spec := domain.RoutingSpec{
		EgressInterface: "wgcf",
		MasterIP:        "203.0.113.1",
		DirectCIDRs:     []string{"10.0.0.0/8"},
		ClientCIDR:      "10.81.0.0/24",
	}
	// All four managed prefs (100 master, 110 direct, 200 fwmark, 300 egress).
	fullRules := "0:\tfrom all lookup local\n" +
		"100:\tfrom all to 203.0.113.1 lookup main\n" +
		"110:\tfrom all to 10.0.0.0/8 lookup main\n" +
		"200:\tfrom all fwmark 0x1 lookup main\n" +
		"300:\tfrom all lookup 51820\n" +
		"32766:\tfrom all lookup main\n"
	egressRoute := "default dev wgcf scope link\n"

	tests := []struct {
		name   string
		rules  string
		routes string
		want   bool
	}{
		{"all present", fullRules, egressRoute, true},
		{"egress rule flushed", strings.Replace(fullRules, "300:\tfrom all lookup 51820\n", "", 1), egressRoute, false},
		{"direct rule flushed", strings.Replace(fullRules, "110:\tfrom all to 10.0.0.0/8 lookup main\n", "", 1), egressRoute, false},
		{"default route gone", fullRules, "", false},
		{"wrong egress iface", fullRules, "default dev eth0 scope link\n", false},
		{"empty kernel", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := KernelReflects(spec, tc.rules, tc.routes); got != tc.want {
				t.Errorf("KernelReflects = %v, want %v", got, tc.want)
			}
		})
	}

	// Direct-egress spec is trivially reflected regardless of kernel state.
	if !KernelReflects(domain.RoutingSpec{}, "", "") {
		t.Error("direct egress spec should always be reflected")
	}
}
