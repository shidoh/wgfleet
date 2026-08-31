package rollout

import (
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// fleet builds a manifest with one master (reserving the named exits) and the
// given exits, each with a usable SSH target.
func fleet(reserve []string, exits ...string) config.FleetSection {
	f := config.FleetSection{
		Masters: []config.MasterConfig{{
			Name:    "wgf0",
			SSH:     config.SSHConfig{Host: "10.0.0.1", KeyPath: "/k"},
			Routing: config.MasterRouting{ReserveExits: reserve},
		}},
	}
	for _, e := range exits {
		f.Exits = append(f.Exits, config.ExitConfig{
			Name: e,
			SSH:  config.SSHConfig{Host: e + ".example", KeyPath: "/k"},
		})
	}
	return f
}

func names(ts []Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuildPlanOrdersReserveTierFirst(t *testing.T) {
	tests := []struct {
		name    string
		reserve []string
		exits   []string
		want    []string
	}{
		{
			name:    "reserve exits precede primary, each alphabetical within its tier",
			reserve: []string{"anz3", "1cnode004", "pn8"},
			exits:   []string{"vn1", "anz3", "vn2", "1cnode004", "pn8"},
			want:    []string{"1cnode004", "anz3", "pn8", "vn1", "vn2"},
		},
		{
			name:    "no reserve declared leaves a single alphabetical primary tier",
			reserve: nil,
			exits:   []string{"vn2", "anz3", "vn1"},
			want:    []string{"anz3", "vn1", "vn2"},
		},
		{
			name:    "every exit in reserve keeps them all first and ordered",
			reserve: []string{"b", "a"},
			exits:   []string{"b", "a"},
			want:    []string{"a", "b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildPlan(fleet(tc.reserve, tc.exits...), readyNodes("v1", tc.exits...), "v2", planNow, 90*time.Second)
			if !eq(names(got.Targets), tc.want) {
				t.Fatalf("order = %v, want %v", names(got.Targets), tc.want)
			}
		})
	}
}

// planNow / readyNodes give BuildPlan a fleet that is actually up. BuildPlan skips
// nodes that have never reported or are not Ready, so an ordering test built on bare
// IDs would exercise the skip path instead of the ordering it means to check.
var planNow = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

func readyNodes(version string, names ...string) []domain.Node {
	out := make([]domain.Node, 0, len(names))
	for _, n := range names {
		out = append(out, domain.Node{
			ID: n, Role: domain.RoleExit, AgentVersion: version,
			State: domain.StateReady, LastSeen: planNow.Add(-5 * time.Second),
		})
	}
	return out
}

func TestBuildPlanTagsTiers(t *testing.T) {
	p := BuildPlan(fleet([]string{"anz3"}, "anz3", "vn1"), readyNodes("v1", "anz3", "vn1"), "v2", planNow, 90*time.Second)
	if len(p.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(p.Targets))
	}
	if p.Targets[0].Tier != TierReserve {
		t.Errorf("anz3 tier = %q, want %q", p.Targets[0].Tier, TierReserve)
	}
	if p.Targets[1].Tier != TierPrimary {
		t.Errorf("vn1 tier = %q, want %q", p.Targets[1].Tier, TierPrimary)
	}
}

// The master is co-located with the controller: upgrading it would restart the
// process driving the rollout. Exclusion must be structural, not a side effect of
// the master happening to be absent from fleet.Exits in some manifests.
func TestBuildPlanNeverIncludesTheMaster(t *testing.T) {
	f := fleet([]string{"anz3"}, "anz3", "vn1")
	nodes := append(readyNodes("v1", "anz3", "vn1"), domain.Node{
		ID: "wgf0", Role: domain.RoleMaster, AgentVersion: "v1",
		State: domain.StateReady, LastSeen: planNow,
	})
	for _, tgt := range BuildPlan(f, nodes, "v2", planNow, 90*time.Second).Targets {
		if tgt.NodeID == "wgf0" {
			t.Fatal("master wgf0 was scheduled for a rolling upgrade")
		}
	}
}

func TestBuildPlanSkipsUpToDateAndUnreachableNodes(t *testing.T) {
	f := fleet(nil, "anz3", "vn1")
	f.Exits = append(f.Exits, config.ExitConfig{Name: "nossh"})           // no SSH target
	nodes := append(readyNodes("v2", "anz3"), readyNodes("v1", "vn1")...) // anz3 already current
	p := BuildPlan(f, nodes, "v2", planNow, 90*time.Second)

	if !eq(names(p.Targets), []string{"vn1"}) {
		t.Fatalf("targets = %v, want [vn1]", names(p.Targets))
	}
	if len(p.Skipped) != 2 {
		t.Fatalf("skipped = %v, want 2 entries (already-current + no-ssh)", p.Skipped)
	}
	if p.Outdated() != 1 {
		t.Errorf("Outdated() = %d, want 1", p.Outdated())
	}
}

func TestBuildPlanCarriesCurrentVersion(t *testing.T) {
	p := BuildPlan(fleet(nil, "vn1"), readyNodes("june-build", "vn1"), "v2", planNow, 90*time.Second)
	if len(p.Targets) != 1 || p.Targets[0].Current != "june-build" {
		t.Fatalf("targets = %+v, want one carrying Current=june-build", p.Targets)
	}
}
