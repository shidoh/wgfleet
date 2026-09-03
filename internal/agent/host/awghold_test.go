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

// TestAWGHoldPlannerSurvivesBusyDpkgLock is the vn1/vn2 failure of 2026-09-03:
// `apt-mark hold` collided with unattended-upgrades holding the dpkg frontend
// lock, the action returned that error, and the WHOLE reconcile pass failed —
// node Error, alert fired, and the next pass 30s later fixed it by itself. The
// hold is convergent by construction (every pass re-checks and re-applies), so a
// lock held by someone else is "not now", not a failure worth failing a pass for.
func TestAWGHoldPlannerSurvivesBusyDpkgLock(t *testing.T) {
	busy := errors.New(`apt-mark hold amneziawg-dkms: exit status 100: dpkg: error: ` +
		`dpkg frontend lock was locked by another process with pid 15154`)
	p := awgHoldPlanner{
		state: stateFn(awgAptPackages, nil),
		hold:  func(context.Context, []string) error { return busy },
	}
	// Must NOT fail the pass.
	applyHold(t, p)
}

// TestAWGHoldPlannerStillFailsOnRealError guards the other half: swallowing a
// busy lock must not turn into swallowing everything. A hold that fails for any
// other reason (no permission, apt broken) still has to surface, or the pin
// silently stops existing and an automatic upgrade splits the AWG generation.
func TestAWGHoldPlannerStillFailsOnRealError(t *testing.T) {
	p := awgHoldPlanner{
		state: stateFn(awgAptPackages, nil),
		hold:  func(context.Context, []string) error { return errors.New("permission denied") },
	}
	_, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), domain.NodeSpec{}, reconcile.ModeApply)
	if err == nil {
		t.Fatal("a non-lock hold failure must fail the pass")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("want the underlying error surfaced, got: %v", err)
	}
}

// TestIsDpkgLockBusy pins the classifier to the exact strings apt/dpkg emit, in
// both the frontend-lock and the lock-file-open forms.
func TestIsDpkgLockBusy(t *testing.T) {
	busy := []string{
		"dpkg: error: dpkg frontend lock was locked by another process with pid 15154",
		"E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 999",
		"Could not get lock /var/lib/apt/lists/lock",
		"E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?",
	}
	for _, s := range busy {
		if !isDpkgLockBusy(s) {
			t.Errorf("should be recognised as a busy lock: %q", s)
		}
	}
	for _, s := range []string{"permission denied", "E: Unable to locate package amneziawg", ""} {
		if isDpkgLockBusy(s) {
			t.Errorf("must NOT be treated as a busy lock: %q", s)
		}
	}
}
