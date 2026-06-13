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
	if got := s.Step(ctx, warpDirect, domain.EgressReachOK, recoverer(false)); got != domain.EgressWARP {
		t.Fatalf("ok must stay on warp, got %q", got)
	}
	// degraded keeps warp (transient).
	if got := s.Step(ctx, warpDirect, domain.EgressReachDegraded, recoverer(false)); got != domain.EgressWARP {
		t.Fatalf("degraded must stay on warp, got %q", got)
	}
	// blocked demotes to direct.
	if got := s.Step(ctx, warpDirect, domain.EgressReachBlocked, recoverer(false)); got != domain.EgressDirect {
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
	if got := s.Step(ctx, chain, domain.EgressReachBlocked, recoverer(false)); got != domain.EgressWARP {
		t.Errorf("blocked with no fallback must stay on warp, got %q", got)
	}
}

func TestSelectorPromotesAfterSustainedRecovery(t *testing.T) {
	ctx := context.Background()
	s := Selector{RecoverPasses: 2}
	// Demote first.
	s.Step(ctx, warpDirect, domain.EgressReachBlocked, recoverer(false))

	// One recovery success is not enough (needs 2 consecutive).
	if got := s.Step(ctx, warpDirect, "", recoverer(true)); got != domain.EgressDirect {
		t.Fatalf("single recovery must not promote yet, got %q", got)
	}
	// Second consecutive success promotes back to warp.
	if got := s.Step(ctx, warpDirect, "", recoverer(true)); got != domain.EgressWARP {
		t.Fatalf("sustained recovery must promote to warp, got %q", got)
	}
}

func TestSelectorRecoveryStreakResetsOnFailure(t *testing.T) {
	ctx := context.Background()
	s := Selector{RecoverPasses: 2}
	s.Step(ctx, warpDirect, domain.EgressReachBlocked, recoverer(false)) // → direct

	s.Step(ctx, warpDirect, "", recoverer(true))  // 1 success
	s.Step(ctx, warpDirect, "", recoverer(false)) // resets streak
	if got := s.Step(ctx, warpDirect, "", recoverer(true)); got != domain.EgressDirect {
		t.Fatalf("streak should have reset; one success must not promote, got %q", got)
	}
	if got := s.Step(ctx, warpDirect, "", recoverer(true)); got != domain.EgressWARP {
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
