package main

import (
	"testing"

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
