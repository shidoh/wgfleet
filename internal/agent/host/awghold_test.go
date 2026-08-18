package host

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// stateFn builds an awgHoldPlanner state func from two package name sets.
func stateFn(installed, held []string) func(context.Context) (map[string]bool, map[string]bool, error) {
	set := func(ss []string) map[string]bool {
		m := make(map[string]bool, len(ss))
		for _, s := range ss {
			m[s] = true
		}
		return m
	}
	return func(context.Context) (map[string]bool, map[string]bool, error) {
		return set(installed), set(held), nil
	}
}

func planHold(t *testing.T, p awgHoldPlanner) []reconcile.Action {
	t.Helper()
	acts, err := p.Plan(context.Background(), domain.NodeSpec{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return acts
}

// applyHold runs the planner through the engine in apply mode, which is the only
// way an action's effect fires (Action.apply is unexported by design).
func applyHold(t *testing.T, p awgHoldPlanner) {
	t.Helper()
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), domain.NodeSpec{}, reconcile.ModeApply); err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// TestAWGHoldPlannerHoldsUnheldPackages is the vn1/vn2 drift: the AmneziaWG
// packages are installed but nothing holds them, while unattended-upgrades is on.
// An automatic dkms/tools bump flips the node's AWG generation, and since AWG 3.0
// broke the netlink ABI between tools and module, a half-applied upgrade takes the
// interface down entirely ("attribute type 14 has an invalid length").
func TestAWGHoldPlannerHoldsUnheldPackages(t *testing.T) {
	var gotHeld []string
	p := awgHoldPlanner{
		state: stateFn(awgAptPackages, nil),
		hold: func(_ context.Context, pkgs []string) error {
			gotHeld = pkgs
			return nil
		},
	}
	acts := planHold(t, p)
	if len(acts) != 1 || !acts[0].Changes() {
		t.Fatalf("expected one changing action, got %+v", acts)
	}
	for _, want := range awgAptPackages {
		if !strings.Contains(acts[0].Display, want) {
			t.Errorf("plan display should name %q, got %q", want, acts[0].Display)
		}
	}
	applyHold(t, p)
	if len(gotHeld) != len(awgAptPackages) {
		t.Errorf("held %v, want all of %v", gotHeld, awgAptPackages)
	}
}

// TestAWGHoldPlannerNoOpWhenAllHeld keeps the planner quiet on a converged node —
// it must not re-run apt-mark on every 30s pass.
func TestAWGHoldPlannerNoOpWhenAllHeld(t *testing.T) {
	p := awgHoldPlanner{
		state: stateFn(awgAptPackages, awgAptPackages),
		hold: func(context.Context, []string) error {
			t.Error("must not hold when everything is already held")
			return nil
		},
	}
	acts := planHold(t, p)
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("expected a single no-change action, got %+v", acts)
	}
}

// TestAWGHoldPlannerHoldsOnlyInstalled proves a package that is not installed is
// not passed to apt-mark: `apt-mark hold` on an unknown package fails the whole
// call, which would take the other two down with it. The master, for one, runs the
// tools inside the wg-easy container and need not have them on the host.
func TestAWGHoldPlannerHoldsOnlyInstalled(t *testing.T) {
	var gotHeld []string
	p := awgHoldPlanner{
		state: stateFn([]string{"amneziawg-dkms"}, nil),
		hold:  func(_ context.Context, pkgs []string) error { gotHeld = pkgs; return nil },
	}
	acts := planHold(t, p)
	if !acts[0].Changes() {
		t.Fatal("expected a changing action")
	}
	applyHold(t, p)
	if len(gotHeld) != 1 || gotHeld[0] != "amneziawg-dkms" {
		t.Errorf("held %v, want only the installed package", gotHeld)
	}
}

// TestAWGHoldPlannerNoOpWithoutAWG covers a node that has no AmneziaWG packages at
// all — nothing to pin, and no error either.
func TestAWGHoldPlannerNoOpWithoutAWG(t *testing.T) {
	p := awgHoldPlanner{
		state: stateFn(nil, nil),
		hold:  func(context.Context, []string) error { t.Error("nothing to hold"); return nil },
	}
	acts := planHold(t, p)
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("expected a single no-change action, got %+v", acts)
	}
}

// TestAWGHoldPlannerSurfacesStateError proves a failing probe is reported rather
// than read as "nothing to do" — a planner that cannot see the node's state must
// not silently claim convergence.
func TestAWGHoldPlannerSurfacesStateError(t *testing.T) {
	p := awgHoldPlanner{
		state: func(context.Context) (map[string]bool, map[string]bool, error) {
			return nil, nil, errors.New("dpkg-query exploded")
		},
	}
	if _, err := p.Plan(context.Background(), domain.NodeSpec{}); err == nil {
		t.Fatal("expected the probe failure to surface")
	}
}
