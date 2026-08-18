package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/restart"
)

// TestSelfHealRestartIsThrottled is the crash-loop guard on the restart that hurts
// most: `docker compose restart mihomo` drops EVERY client's connection. The
// duplicate-device condition is not self-clearing if the restart does not fix it,
// so without a governor this fires on every 30s pass, forever, disconnecting all
// clients each time.
func TestSelfHealRestartIsThrottled(t *testing.T) {
	gov := restart.New(nil)
	restarts := 0
	pl := mihomoWGDupPlanner{
		compose:     "/dev/null",
		peerSockets: func(string) (int, bool) { return 2, true }, // condition never clears
		restart:     func(context.Context) error { restarts++; return nil },
		gov:         gov,
	}

	// The free budget runs unthrottled — one restart usually fixes a transient leak.
	for i := 0; i < restart.FreeBudget; i++ {
		if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), dupSpec(), reconcile.ModeApply); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if restarts != restart.FreeBudget {
		t.Fatalf("applied %d restarts in the free budget, want %d", restarts, restart.FreeBudget)
	}

	// Past it the restart must be suppressed rather than repeated every pass.
	for i := 0; i < 5; i++ {
		if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), dupSpec(), reconcile.ModeApply); err != nil {
			t.Fatalf("throttled pass %d: %v", i, err)
		}
	}
	if restarts != restart.FreeBudget {
		t.Errorf("restarts = %d after throttling, want it to stay at %d", restarts, restart.FreeBudget)
	}
}

// TestThrottledPassExplainsItself — a suppressed restart must say so, not look
// like a healthy no-op. Otherwise an operator watching the plan sees "nothing to
// do" while the data plane is broken.
func TestThrottledPassExplainsItself(t *testing.T) {
	gov := restart.New(nil)
	pl := mihomoWGDupPlanner{
		compose:     "/dev/null",
		peerSockets: func(string) (int, bool) { return 2, true },
		restart:     func(context.Context) error { return nil },
		gov:         gov,
	}
	for i := 0; i < restart.FreeBudget; i++ {
		_, _ = reconcile.NewEngine(nil, pl).Reconcile(context.Background(), dupSpec(), reconcile.ModeApply)
	}
	acts, err := pl.Plan(context.Background(), dupSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("expected a single no-change action, got %+v", acts)
	}
	if s := acts[0].Summary; !strings.Contains(s, "throttl") && !strings.Contains(s, "suppress") {
		t.Errorf("summary %q does not explain the suppression", s)
	}
}

// TestPlanModeDoesNotSpendBudget — a dry run must never consume a service's
// restart budget, or repeatedly inspecting a broken master would throttle the very
// repair the operator is about to authorise.
func TestPlanModeDoesNotSpendBudget(t *testing.T) {
	gov := restart.New(nil)
	pl := mihomoWGDupPlanner{
		compose:     "/dev/null",
		peerSockets: func(string) (int, bool) { return 2, true },
		restart:     func(context.Context) error { return nil },
		gov:         gov,
	}
	for i := 0; i < restart.FreeBudget*3; i++ {
		if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), dupSpec(), reconcile.ModePlan); err != nil {
			t.Fatalf("plan pass %d: %v", i, err)
		}
	}
	if ok, _ := gov.Allow(restartKeyMihomo); !ok {
		t.Error("plan-mode passes must not consume the restart budget")
	}
}

// TestNilGovernorKeepsOldBehaviour — every planner takes the governor optionally,
// and a nil one must mean "exactly as before", never "self-healing quietly off".
func TestNilGovernorKeepsOldBehaviour(t *testing.T) {
	restarts := 0
	pl := mihomoWGDupPlanner{
		compose:     "/dev/null",
		peerSockets: func(string) (int, bool) { return 2, true },
		restart:     func(context.Context) error { restarts++; return nil },
	}
	for i := 0; i < restart.FreeBudget+3; i++ {
		_, _ = reconcile.NewEngine(nil, pl).Reconcile(context.Background(), dupSpec(), reconcile.ModeApply)
	}
	if restarts != restart.FreeBudget+3 {
		t.Errorf("restarts = %d, want every pass to restart with no governor", restarts)
	}
}
