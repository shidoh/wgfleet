package main

import (
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/master"
	"github.com/shidoh/wgfleet/internal/domain"
)

func TestExitHealthForMaster(t *testing.T) {
	spec := domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			ExitTunnels: []domain.ExitTunnel{{Name: "exit-de-1"}, {Name: "exit-nl-1"}},
		},
	}
	js := []byte(`{"proxies":{
	  "exit-de-1":{"alive":true,"history":[{"time":"2026-06-26T10:00:00Z","delay":42}]},
	  "exit-nl-1":{"alive":false,"history":[]},
	  "wg-best":{"now":"exit-de-1"}
	}}`)

	got := exitHealthForMaster(js, spec)
	if len(got) != 2 || got[0].Name != "exit-de-1" || !got[0].Alive || !got[0].Selected {
		t.Fatalf("master exit health mismatch: %+v", got)
	}

	// Non-master ⇒ nil.
	if h := exitHealthForMaster(js, domain.NodeSpec{Role: domain.RoleExit}); h != nil {
		t.Fatalf("exit role should yield nil, got %+v", h)
	}
	// Garbage JSON ⇒ nil (never fails the caller).
	if h := exitHealthForMaster([]byte("nope"), spec); h != nil {
		t.Fatalf("bad JSON should yield nil, got %+v", h)
	}
}

// mihomo's snapshot says WHAT the load balancer is doing; the tier selector knows
// WHY. The status report is the only channel that reaches the console, so the two
// are joined before it is sent — otherwise the reason stays on the master, in a
// journal nobody reads at 4am.
func TestExitHealthCarriesTheTierVerdict(t *testing.T) {
	health := []domain.ExitTunnelHealth{
		{Name: "vn1", Alive: false},
		{Name: "vn2", Alive: true, Selected: true},
		{Name: "1cnode004", Alive: true},
	}
	since := time.Unix(1757583219, 0).UTC()
	verdicts := map[string]master.ExitVerdict{
		"vn1": {HeldOut: true, Reachable: 0, Probed: 4, Since: since},
		"vn2": {HeldOut: false, Reachable: 4, Probed: 4},
	}

	got := withTierVerdicts(health, verdicts)

	if !got[0].HeldOut || got[0].Probed != 4 || !got[0].HeldSince.Equal(since) {
		t.Errorf("vn1 must carry the verdict that held it out: %+v", got[0])
	}
	if got[1].HeldOut || !got[1].HeldSince.IsZero() || got[1].Reachable != 4 {
		t.Errorf("a carrying exit must carry its clean probe and no hold: %+v", got[1])
	}
	// The idle reserve tier is in no rotation, so there is no verdict about it —
	// and inventing one ("not held out") would read as a judgement nobody took.
	if got[2].HeldOut || got[2].Probed != 0 {
		t.Errorf("an unjudged exit must stay unjudged: %+v", got[2])
	}
}
