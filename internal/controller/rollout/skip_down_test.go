package rollout

import (
	"strings"
	"testing"
	"time"

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
		{ID: "vn2", AgentVersion: "v1", State: domain.StateError, LastSeen: now.Add(-10 * time.Second)},
	}
	p := BuildPlan(fleet(nil, "anz3", "vn1", "vn2"), nodes, "v2", now, 90*time.Second)

	var targets []string
	for _, t := range p.Targets {
		targets = append(targets, t.NodeID)
	}
	if len(targets) != 1 || targets[0] != "anz3" {
		t.Fatalf("targets = %v, want only the healthy node", targets)
	}

	reasons := map[string]string{}
	for _, s := range p.Skipped {
		reasons[s.Name] = s.Reason
	}
	if !strings.Contains(reasons["vn1"], "reported") {
		t.Errorf("stale node skipped without saying why: %q", reasons["vn1"])
	}
	if !strings.Contains(reasons["vn2"], "Error") {
		t.Errorf("errored node skipped without naming its state: %q", reasons["vn2"])
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
