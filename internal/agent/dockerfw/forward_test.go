package dockerfw

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

func changing(acts []reconcile.Action, sub string) bool {
	for _, a := range acts {
		if a.Changes() && strings.Contains(a.Summary, sub) {
			return true
		}
	}
	return false
}

func anyChange(acts []reconcile.Action) bool {
	for _, a := range acts {
		if a.Changes() {
			return true
		}
	}
	return false
}

// exit-flavoured planner: iface awg0, "client→egress" label.
func TestForwardPlanner_Exit(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleExit}

	// ip_forward off + DOCKER-USER present + rules absent ⇒ enable + insert both.
	pl := ForwardPlanner{
		component:    "exit forwarding",
		iface:        "awg0",
		forwardLabel: "accept client→egress forwarding (DOCKER-USER)",
		forwardOn:    func() bool { return false },
		chainExists:  func() bool { return true },
		rulePresent:  func([]string) bool { return false },
	}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !changing(acts, "enable IPv4 forwarding") ||
		!changing(acts, "client→egress") || !changing(acts, "return traffic") {
		t.Errorf("expected ip_forward + both DOCKER-USER inserts, got %+v", acts)
	}

	// DOCKER-USER absent (docker not up) ⇒ defer, never insert.
	deferred := ForwardPlanner{
		component: "exit forwarding", iface: "awg0",
		forwardLabel: "accept client→egress forwarding (DOCKER-USER)",
		forwardOn:    func() bool { return true },
		chainExists:  func() bool { return false },
		rulePresent:  func([]string) bool { return false },
	}
	acts2, _ := deferred.Plan(context.Background(), spec)
	if anyChange(acts2) {
		t.Errorf("expected no insert while DOCKER-USER absent, got %+v", acts2)
	}
}

// master-flavoured planner: iface wg0, "client→uplink" label.
func TestForwardPlanner_Master(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{}}

	t.Run("applies when missing", func(t *testing.T) {
		pl := ForwardPlanner{
			component:    "master forwarding",
			iface:        "wg0",
			forwardLabel: "accept client→uplink forwarding (DOCKER-USER)",
			forwardOn:    func() bool { return false },
			chainExists:  func() bool { return true },
			rulePresent:  func([]string) bool { return false },
		}
		acts, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if !changing(acts, "enable IPv4 forwarding") {
			t.Errorf("expected ip_forward enable, got %+v", acts)
		}
		if !changing(acts, "client→uplink") || !changing(acts, "return traffic") {
			t.Errorf("expected both DOCKER-USER inserts, got %+v", acts)
		}
	})

	t.Run("no change when present", func(t *testing.T) {
		pl := ForwardPlanner{
			component: "master forwarding", iface: "wg0",
			forwardLabel: "accept client→uplink forwarding (DOCKER-USER)",
			forwardOn:    func() bool { return true },
			chainExists:  func() bool { return true },
			rulePresent:  func([]string) bool { return true },
		}
		acts, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if anyChange(acts) {
			t.Errorf("expected no-change when forwarding already set, got %+v", acts)
		}
	})

	t.Run("defers when docker not up", func(t *testing.T) {
		pl := ForwardPlanner{
			component: "master forwarding", iface: "wg0",
			forwardLabel: "accept client→uplink forwarding (DOCKER-USER)",
			forwardOn:    func() bool { return true },
			chainExists:  func() bool { return false },
			rulePresent:  func([]string) bool { return false },
		}
		acts, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if anyChange(acts) {
			t.Errorf("expected no insert while DOCKER-USER is absent, got %+v", acts)
		}
	})
}

// NewForwardPlanner applies the fallback interface when iface is empty.
func TestNewForwardPlannerFallback(t *testing.T) {
	p := NewForwardPlanner("c", "", "awg0", "label")
	if p.iface != "awg0" {
		t.Errorf("fallback iface: got %q want awg0", p.iface)
	}
	p2 := NewForwardPlanner("c", "wg0", "awg0", "label")
	if p2.iface != "wg0" {
		t.Errorf("explicit iface: got %q want wg0", p2.iface)
	}
}
