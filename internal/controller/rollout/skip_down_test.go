package rollout

import (
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// A node that is already down gets upgraded anyway: the binary lands, the agent is
// restarted, the come-back gate waits its full timeout, the node is ROLLED BACK, and
// because a failure halts the run (rollout stops at the first one) the whole rollout
// dies there. Reserve sorts first, so one dead reserve node blocks every primary —
// and the dry-run gave no hint, because the plan listed it as a normal target.
func TestPlanSkipsNodesThatAreNotUp(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	nodes := []domain.Node{
		{ID: "anz3", AgentVersion: "v1", State: domain.StateReady, LastSeen: now.Add(-10 * time.Second)},
		{ID: "vn1", AgentVersion: "v1", State: domain.StateReady, LastSeen: now.Add(-2 * time.Hour)},
		// Degraded but REPORTING: it must stay a target — it may be degraded by the
		// very bug this rollout carries the fix for.
		{ID: "vn2", AgentVersion: "v1", State: domain.StateDegraded, LastSeen: now.Add(-10 * time.Second)},
	}
	p := BuildPlan(fleet(nil, "anz3", "vn1", "vn2"), nodes, "v2", now, 90*time.Second)

	var targets []string
	for _, t := range p.Targets {
		targets = append(targets, t.NodeID)
	}
	if len(targets) != 2 || targets[0] != "anz3" || targets[1] != "vn2" {
		t.Fatalf("targets = %v, want the reporting nodes (healthy + degraded)", targets)
	}

	reasons := map[string]string{}
	for _, s := range p.Skipped {
		reasons[s.Name] = s.Reason
	}
	if !strings.Contains(reasons["vn1"], "reported") {
		t.Errorf("stale node skipped without saying why: %q", reasons["vn1"])
	}
	if _, skipped := reasons["vn2"]; skipped {
		t.Errorf("a degraded but reporting node was skipped: %q", reasons["vn2"])
	}
}

// A node with no store row at all has never reported; upgrading it is the same
// wasted round-trip and the same halt.
func TestPlanSkipsNodesThatNeverReported(t *testing.T) {
	now := time.Now()
	p := BuildPlan(fleet(nil, "ghost"), nil, "v2", now, 90*time.Second)
	if len(p.Targets) != 0 {
		t.Fatalf("an unknown node was made a target: %+v", p.Targets)
	}
	if len(p.Skipped) != 1 {
		t.Fatalf("skipped = %+v, want one entry accounting for it", p.Skipped)
	}
}

// reconcile_interval is operator-configurable up to an hour. A fixed 90s staleness
// bound made any node on a slower cadence permanently and silently ineligible for
// every fleet-wide rollout — healthy, reporting exactly on schedule, and skipped.
func TestFreshnessBoundFollowsTheReconcileCadence(t *testing.T) {
	var f config.FleetSection
	if got := FreshWithinFor(f); got != DefaultFreshWithin {
		t.Errorf("default cadence gave %v, want the %v floor", got, DefaultFreshWithin)
	}

	f.ReconcileInterval = 5 * time.Minute
	if got := FreshWithinFor(f); got != 10*time.Minute {
		t.Errorf("5m cadence gave %v, want two intervals", got)
	}

	// The end-to-end effect: a node reporting on a 5-minute cadence stays a target.
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	nodes := []domain.Node{{
		ID: "slowpoke", AgentVersion: "v1", State: domain.StateReady,
		LastSeen: now.Add(-4 * time.Minute),
	}}
	p := BuildPlan(fleet(nil, "slowpoke"), nodes, "v2", now, FreshWithinFor(f))
	if len(p.Targets) != 1 {
		t.Fatalf("a node on a 5m cadence was skipped: %+v", p.Skipped)
	}
}
