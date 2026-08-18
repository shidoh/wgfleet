package rollout

import (
	"context"
	"errors"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// untouchedErr is a stand-in for the error provmgr returns when an upgrade fails
// BEFORE it modifies anything on the node. The coordinator must recognise it
// structurally (via the NodeUntouched behaviour), not by importing the package
// that produces it.
type untouchedErr struct{ error }

func (untouchedErr) NodeUntouched() bool { return true }

// TestNoRollbackWhenNodeWasNeverTouched is the pn8 regression of 2026-08-18.
//
// The upgrade failed at its very first step — the SSH dial timed out — so nothing
// was uploaded, no rollback snapshot was taken in that attempt and the agent was
// never restarted. The coordinator rolled the node back anyway, restoring a STALE
// .prev left by some earlier upgrade. A healthy node running wire 6 was downgraded
// to wire 5 by an upgrade attempt that never reached it.
//
// "It failed, so roll it back" only holds when there was something to roll back.
func TestNoRollbackWhenNodeWasNeverTouched(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	up.failOn["pn8"] = untouchedErr{errors.New(`ssh dial "pn8": i/o timeout`)}
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node { return domain.Node{} }}
	c := testCoordinator(up, st, clk)

	_ = c.Start(context.Background(), planOf("pn8"))
	c.Wait()

	if got := up.restored(); len(got) != 0 {
		t.Errorf("rolled back %v — a node the upgrade never reached must not be touched", got)
	}
	s := c.Snapshot()
	if s.Nodes[0].Phase != PhaseFailed {
		t.Errorf("phase = %q, want %q (failed, not rolled-back)", s.Nodes[0].Phase, PhaseFailed)
	}
	if s.Nodes[0].RolledBack {
		t.Error("RolledBack must stay false when no rollback ran")
	}
	if got := s.Nodes[0].Err; got == "" || !contains(got, "i/o timeout") {
		t.Errorf("node error %q does not carry the cause", got)
	}
}

// TestRollbackStillRunsWhenTheNodeWasModified — the guard must be narrow. A
// failure anywhere at or after the upload DID displace the binary, and skipping
// the rollback there would strand the node on the build that just failed.
func TestRollbackStillRunsWhenTheNodeWasModified(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	up.failOn["anz3"] = errors.New("sha256 mismatch after upload")
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node { return domain.Node{} }}
	c := testCoordinator(up, st, clk)

	_ = c.Start(context.Background(), planOf("anz3"))
	c.Wait()

	if got := up.restored(); len(got) != 1 || got[0] != "anz3" {
		t.Errorf("restored %v, want the node rolled back", got)
	}
	if s := c.Snapshot(); s.Nodes[0].Phase != PhaseRolledBack {
		t.Errorf("phase = %q, want %q", s.Nodes[0].Phase, PhaseRolledBack)
	}
}

// TestUntouchedFailureStillHaltsTheRollout — skipping the rollback must not make
// the failure softer. An unreachable node still means the fleet is not converging
// as planned, and marching on would upgrade the primary tier while a reserve node
// silently lags.
func TestUntouchedFailureStillHaltsTheRollout(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	up.failOn["pn8"] = untouchedErr{errors.New("ssh dial: i/o timeout")}
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node { return domain.Node{} }}
	c := testCoordinator(up, st, clk)

	_ = c.Start(context.Background(), planOf("pn8", "vn0", "vn1"))
	c.Wait()

	ph := phases(c.Snapshot())
	if ph["vn0"] != PhaseSkipped || ph["vn1"] != PhaseSkipped {
		t.Errorf("later nodes = %v, want both skipped", ph)
	}
	if got := up.touched(); len(got) != 1 || got[0] != "pn8" {
		t.Errorf("upgraded %v, want only the failing node attempted", got)
	}
}
