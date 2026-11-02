package egress

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

var warpDirect = []domain.EgressMethod{domain.EgressWARP, domain.EgressDirect}

func recoverer(ok bool) RecoverProbe {
	return func(context.Context) bool { return ok }
}

func TestSelectorActiveDefaultsToPreferred(t *testing.T) {
	var s Selector
	if got := s.Active(warpDirect); got != domain.EgressWARP {
		t.Errorf("Active default = %q, want warp", got)
	}
	if got := s.Active(nil); got != domain.EgressWARP {
		t.Errorf("Active with nil chain should keep the prior active, got %q", got)
	}
}

func TestSelectorDemotesOnBlock(t *testing.T) {
	ctx := context.Background()
	var s Selector

	// ok keeps warp.
	if got := s.Step(ctx, warpDirect, domain.EgressReachOK, false, recoverer(false)); got != domain.EgressWARP {
		t.Fatalf("ok must stay on warp, got %q", got)
	}
	// degraded keeps warp (transient).
	if got := s.Step(ctx, warpDirect, domain.EgressReachDegraded, false, recoverer(false)); got != domain.EgressWARP {
		t.Fatalf("degraded must stay on warp, got %q", got)
	}
	// blocked demotes to direct.
	if got := s.Step(ctx, warpDirect, domain.EgressReachBlocked, false, recoverer(false)); got != domain.EgressDirect {
		t.Fatalf("blocked must demote to direct, got %q", got)
	}
	if got := s.Active(warpDirect); got != domain.EgressDirect {
		t.Errorf("active after demotion = %q, want direct", got)
	}
}

func TestSelectorNoFallbackStaysPut(t *testing.T) {
	ctx := context.Background()
	var s Selector
	chain := []domain.EgressMethod{domain.EgressWARP} // no fallback
	if got := s.Step(ctx, chain, domain.EgressReachBlocked, false, recoverer(false)); got != domain.EgressWARP {
		t.Errorf("blocked with no fallback must stay on warp, got %q", got)
	}
}

func TestSelectorDemotesOnThroughputCollapse(t *testing.T) {
	ctx := context.Background()
	var s Selector
	// Reachability is fine (ok), but throughput collapsed ⇒ demote to the fallback
	// anyway — a fast direct path beats a throttled WARP (ADR-0021, the exit-3 case).
	if got := s.Step(ctx, warpDirect, domain.EgressReachOK, true, recoverer(false)); got != domain.EgressDirect {
		t.Fatalf("throughput collapse must demote to direct, got %q", got)
	}
	// With no fallback, a throughput collapse keeps the exit put (controller
	// auto-suspends it from the LB instead).
	var s2 Selector
	chain := []domain.EgressMethod{domain.EgressWARP}
	if got := s2.Step(ctx, chain, domain.EgressReachOK, true, recoverer(false)); got != domain.EgressWARP {
		t.Errorf("throughput collapse with no fallback must stay put, got %q", got)
	}
}

func TestSelectorPromotesAfterSustainedRecovery(t *testing.T) {
	ctx := context.Background()
	s := Selector{RecoverPasses: 2}
	// Demote first.
	s.Step(ctx, warpDirect, domain.EgressReachBlocked, false, recoverer(false))

	// One recovery success is not enough (needs 2 consecutive).
	if got := s.Step(ctx, warpDirect, "", false, recoverer(true)); got != domain.EgressDirect {
		t.Fatalf("single recovery must not promote yet, got %q", got)
	}
	// Second consecutive success promotes back to warp.
	if got := s.Step(ctx, warpDirect, "", false, recoverer(true)); got != domain.EgressWARP {
		t.Fatalf("sustained recovery must promote to warp, got %q", got)
	}
}

func TestSelectorRecoveryStreakResetsOnFailure(t *testing.T) {
	ctx := context.Background()
	s := Selector{RecoverPasses: 2}
	s.Step(ctx, warpDirect, domain.EgressReachBlocked, false, recoverer(false)) // → direct

	s.Step(ctx, warpDirect, "", false, recoverer(true))  // 1 success
	s.Step(ctx, warpDirect, "", false, recoverer(false)) // resets streak
	if got := s.Step(ctx, warpDirect, "", false, recoverer(true)); got != domain.EgressDirect {
		t.Fatalf("streak should have reset; one success must not promote, got %q", got)
	}
	if got := s.Step(ctx, warpDirect, "", false, recoverer(true)); got != domain.EgressWARP {
		t.Fatalf("two fresh consecutive successes must promote, got %q", got)
	}
}

func TestEffectiveSpec(t *testing.T) {
	base := domain.NodeSpec{
		Role:        domain.RoleExit,
		Egress:      domain.EgressWARP,
		EgressChain: warpDirect,
		Routing:     domain.RoutingSpec{EgressInterface: "wgcf", MasterIP: "203.0.113.1"},
	}

	// Active == preferred ⇒ no-op (warp egress unchanged).
	if eff := EffectiveSpec(base, domain.EgressWARP); eff.Routing.EgressInterface != "wgcf" {
		t.Errorf("preferred active must leave routing at wgcf, got %q", eff.Routing.EgressInterface)
	}

	// Failed over to direct ⇒ Egress=direct, no policy routing, but chain preserved
	// (so the WARP planner keeps wgcf up).
	eff := EffectiveSpec(base, domain.EgressDirect)
	if eff.Egress != domain.EgressDirect {
		t.Errorf("effective egress = %q, want direct", eff.Egress)
	}
	if eff.Routing.EgressInterface != "" {
		t.Errorf("direct egress must clear the routing interface, got %q", eff.Routing.EgressInterface)
	}
	if !eff.EgressChainHas(domain.EgressWARP) {
		t.Error("effective spec must preserve the chain so wgcf stays up for recovery")
	}
	if base.Routing.EgressInterface != "wgcf" {
		t.Error("EffectiveSpec must not mutate the input spec")
	}

	// Active warp while preferred is direct ⇒ routing points at wgcf (covers the
	// promote-into-warp branch).
	d := domain.NodeSpec{Egress: domain.EgressDirect, EgressChain: []domain.EgressMethod{domain.EgressDirect, domain.EgressWARP}}
	if eff := EffectiveSpec(d, domain.EgressWARP); eff.Routing.EgressInterface != WARPInterface {
		t.Errorf("warp active must route via wgcf, got %q", eff.Routing.EgressInterface)
	}
}

// The operator moved the exit from direct to WARP in the manifest. The selector
// still held "direct" from the old chain and read it as a fallback it was failed
// over to — and stayed there for as long as the recovery probe did not pass, on
// an egress the manifest no longer lists. Found on the stand: the exit
// ran direct until its agent was restarted.
func TestSelectorDropsAnActiveEgressTheChainNoLongerLists(t *testing.T) {
	ctx := context.Background()
	never := func(context.Context) bool { return false }
	var s Selector
	if got := s.Step(ctx, []domain.EgressMethod{domain.EgressDirect}, "", false, never); got != domain.EgressDirect {
		t.Fatalf("active = %q, want direct", got)
	}
	warpOnly := []domain.EgressMethod{domain.EgressWARP}
	if got := s.Active(warpOnly); got != domain.EgressWARP {
		t.Errorf("Active = %q after the chain became [warp], want warp", got)
	}
	if got := s.Step(ctx, warpOnly, "", false, never); got != domain.EgressWARP {
		t.Errorf("Step = %q after the chain became [warp], want warp", got)
	}
}

// A fallback the chain still lists is a real failover and is kept.
func TestSelectorKeepsAFallbackTheChainStillLists(t *testing.T) {
	ctx := context.Background()
	never := func(context.Context) bool { return false }
	chain := []domain.EgressMethod{domain.EgressWARP, domain.EgressDirect}
	var s Selector
	if got := s.Step(ctx, chain, domain.EgressReachBlocked, false, never); got != domain.EgressDirect {
		t.Fatalf("active = %q after a block, want direct", got)
	}
	if got := s.Active(chain); got != domain.EgressDirect {
		t.Errorf("Active = %q, want the fallback kept", got)
	}
	if got := s.Step(ctx, chain, "", false, never); got != domain.EgressDirect {
		t.Errorf("Step = %q, want the fallback kept", got)
	}
}
