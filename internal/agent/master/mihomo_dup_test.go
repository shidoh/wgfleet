package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// dupSpec builds a master spec with one AWG exit and one reality-xhttp exit, so
// tests can assert the planner only counts devices for the AWG one.
func dupSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			ExitTunnels: []domain.ExitTunnel{
				{Name: "vn1", Endpoint: "198.51.100.7:30449", Transport: domain.TransportAWG},
				{Name: "vn2", Endpoint: "198.51.100.8:30228", Transport: domain.TransportRealityXHTTP},
			},
		},
	}
}

func TestWGDupPlannerNoChangeWhenOneDevicePerExit(t *testing.T) {
	pl := mihomoWGDupPlanner{
		peerSockets: func(string) (int, bool) { return 1, true },
		restart:     func(context.Context) error { t.Fatal("must not restart"); return nil },
	}
	actions, err := pl.Plan(context.Background(), dupSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Changes() {
		t.Fatalf("expected a single no-change action, got %+v", actions)
	}
}

func TestWGDupPlannerRestartsOnLeakedDevice(t *testing.T) {
	restarted := false
	pl := mihomoWGDupPlanner{
		peerSockets: func(addr string) (int, bool) {
			if addr == "198.51.100.7:30449" {
				return 2, true // vn1 leaked a second device
			}
			return 1, true
		},
		restart: func(context.Context) error { restarted = true; return nil },
	}
	actions, err := pl.Plan(context.Background(), dupSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !actions[0].Changes() {
		t.Fatalf("expected one change action, got %+v", actions)
	}
	if !strings.Contains(actions[0].Summary, "vn1 (2 devices on 198.51.100.7:30449)") {
		t.Fatalf("summary must name the offending exit and count, got %q", actions[0].Summary)
	}
	if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), dupSpec(), reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if !restarted {
		t.Fatal("apply must restart mihomo")
	}
}

// A reality-xhttp exit dials plain TCP and cannot leak a userspace WG device, so
// its socket count must never trigger the connection-dropping restart.
func TestWGDupPlannerIgnoresRealityExits(t *testing.T) {
	pl := mihomoWGDupPlanner{
		peerSockets: func(addr string) (int, bool) {
			if addr == "198.51.100.8:30228" {
				return 9, true // many TCP-era sockets to the reality exit
			}
			return 1, true
		},
		restart: func(context.Context) error { t.Fatal("must not restart"); return nil },
	}
	actions, err := pl.Plan(context.Background(), dupSpec())
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Changes() {
		t.Fatalf("reality exit must not trigger a restart, got %+v", actions[0])
	}
}

// An unreadable socket table must fail safe: a restart drops every client
// connection, so it must never fire on a guess.
func TestWGDupPlannerFailsSafeWhenSocketTableUnreadable(t *testing.T) {
	pl := mihomoWGDupPlanner{
		peerSockets: func(string) (int, bool) { return 0, false },
		restart:     func(context.Context) error { t.Fatal("must not restart"); return nil },
	}
	actions, err := pl.Plan(context.Background(), dupSpec())
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Changes() {
		t.Fatalf("unreadable socket table must not restart, got %+v", actions[0])
	}
	if !strings.Contains(actions[0].Summary, "unreadable") {
		t.Fatalf("summary must explain the skip, got %q", actions[0].Summary)
	}
}

// An empty Transport means AWG (pre-ADR-0025 back-compat), so it must still be
// checked for leaked devices.
func TestWGDupPlannerTreatsEmptyTransportAsAWG(t *testing.T) {
	spec := domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			ExitTunnels: []domain.ExitTunnel{{Name: "legacy", Endpoint: "198.51.100.9:51820"}},
		},
	}
	pl := mihomoWGDupPlanner{
		peerSockets: func(string) (int, bool) { return 3, true },
		restart:     func(context.Context) error { return nil },
	}
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !actions[0].Changes() {
		t.Fatal("an empty transport is AWG and must be checked")
	}
}

func TestWGDupPlannerRejectsNonMasterSpec(t *testing.T) {
	if _, err := (mihomoWGDupPlanner{}).Plan(context.Background(), domain.NodeSpec{Role: domain.RoleExit}); err == nil {
		t.Fatal("expected an error for a node with no master spec")
	}
}
