package health

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func warpEgress(ok bool) []domain.HealthCheck {
	return []domain.HealthCheck{{Name: "warp-egress", OK: ok}}
}

func confirmStub(ok bool, detail string) Probe {
	return func(context.Context) Result { return Result{OK: ok, Detail: detail} }
}

func TestEgressClassifierNoWARPCheck(t *testing.T) {
	// Direct egress: no warp-egress check ⇒ nothing to classify.
	var c EgressClassifier
	class, chk := c.Classify(context.Background(), []domain.HealthCheck{{Name: "wg-handshake", OK: true}}, nil)
	if class != "" || chk != nil {
		t.Fatalf("no warp-egress check should yield empty classification, got %q / %v", class, chk)
	}
}

func TestEgressClassifierOK(t *testing.T) {
	var c EgressClassifier
	class, chk := c.Classify(context.Background(), warpEgress(true), confirmStub(false, "should not run"))
	if class != domain.EgressReachOK {
		t.Errorf("class = %q, want ok", class)
	}
	if chk == nil || chk.Name != domain.CheckEgressReachability || !chk.OK {
		t.Errorf("ok must yield an OK egress-reachability check, got %+v", chk)
	}
}

func TestEgressClassifierTransientThenBlocked(t *testing.T) {
	c := EgressClassifier{Threshold: 2}
	ctx := context.Background()

	// First failure: below threshold ⇒ degraded (transient), confirm not consulted.
	class, chk := c.Classify(ctx, warpEgress(false), confirmStub(false, "should not run yet"))
	if class != domain.EgressReachDegraded {
		t.Fatalf("first failure must be degraded, got %q", class)
	}
	if !chk.OK {
		t.Error("degraded egress-reachability check must stay OK (not a block)")
	}

	// Second failure: threshold reached + confirm says path unreachable ⇒ blocked.
	class, chk = c.Classify(ctx, warpEgress(false), confirmStub(false, "WARP handshake stale"))
	if class != domain.EgressReachBlocked {
		t.Fatalf("persistent failure + unreachable path must be blocked, got %q", class)
	}
	if chk.OK {
		t.Error("blocked egress-reachability check must be OK=false (the censorship signal)")
	}
}

func TestEgressClassifierDownstreamNotBlocked(t *testing.T) {
	c := EgressClassifier{Threshold: 1}
	// At threshold but the WARP path still handshakes ⇒ downstream, NOT a block.
	class, chk := c.Classify(context.Background(), warpEgress(false), confirmStub(true, "WARP handshake 3s ago"))
	if class != domain.EgressReachDegraded {
		t.Fatalf("reachable path must classify as degraded, not blocked, got %q", class)
	}
	if !chk.OK {
		t.Error("downstream-degraded check must stay OK")
	}
}

func TestEgressClassifierRecoveryResetsStreak(t *testing.T) {
	c := EgressClassifier{Threshold: 2}
	ctx := context.Background()
	// Drive to blocked.
	c.Classify(ctx, warpEgress(false), confirmStub(false, "stale"))
	if class, _ := c.Classify(ctx, warpEgress(false), confirmStub(false, "stale")); class != domain.EgressReachBlocked {
		t.Fatalf("expected blocked, got %q", class)
	}
	// Recovery resets the streak.
	if class, _ := c.Classify(ctx, warpEgress(true), nil); class != domain.EgressReachOK {
		t.Fatalf("recovery must be ok, got %q", class)
	}
	// A single fresh failure is transient again, not immediately blocked.
	if class, _ := c.Classify(ctx, warpEgress(false), confirmStub(false, "stale")); class != domain.EgressReachDegraded {
		t.Errorf("post-recovery single failure must be degraded, got %q", class)
	}
}

func TestNodeStatusEgressBlocked(t *testing.T) {
	blocked := domain.NodeStatus{Checks: []domain.HealthCheck{
		{Name: "wg-handshake", OK: true},
		{Name: domain.CheckEgressReachability, OK: false, Detail: "blocked: ..."},
	}}
	if !blocked.EgressBlocked() {
		t.Error("status with a failing egress-reachability check should report blocked")
	}
	ok := domain.NodeStatus{Checks: []domain.HealthCheck{
		{Name: domain.CheckEgressReachability, OK: true, Detail: "ok: ..."},
	}}
	if ok.EgressBlocked() {
		t.Error("status with a passing egress-reachability check should not report blocked")
	}
	if (domain.NodeStatus{}).EgressBlocked() {
		t.Error("status with no egress-reachability check should not report blocked")
	}
}
