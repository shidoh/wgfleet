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

// TestNoRollbackWhenNodeWasNeverTouched guards against downgrading a node the
// upgrade never reached.
//
// When the upgrade fails at its very first step — the SSH dial times out — nothing
// is uploaded, no rollback snapshot is taken in that attempt and the agent is
// never restarted. Rolling the node back anyway would restore a STALE .prev left
// by some earlier upgrade, downgrading a healthy node to an older wire version by
// an upgrade attempt that never reached it.
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

// An unreachable node is skipped, not rolled back, and the rest of the fleet is
// upgraded anyway.
//
// This is the failure the rollout meets most often — a path that accepts a TCP
// connection and then black-holes — and it says nothing whatsoever about the
// binary. Holding every healthy exit on the old build because one would not
// answer is the outcome a rolling upgrade exists to prevent.
func TestUnreachableNodeIsSkippedAndTheRestAreUpgraded(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	up.failOn["pn8"] = untouchedErr{errors.New("ssh dial: i/o timeout")}
	st := &fakeStore{clock: clk, fn: func(id string, _ int) domain.Node {
		if id == "pn8" {
			return domain.Node{}
		}
		return domain.Node{State: domain.StateReady, AgentVersion: "new", LastSeen: clk.now()}
	}}
	c := testCoordinator(up, st, clk)

	_ = c.Start(context.Background(), planOf("pn8", "vn0", "vn1"))
	c.Wait()

	ph := phases(c.Snapshot())
	if ph["pn8"] != PhaseFailed {
		t.Errorf("pn8 = %q, want %q", ph["pn8"], PhaseFailed)
	}
	if ph["vn0"] != PhaseDone || ph["vn1"] != PhaseDone {
		t.Errorf("later nodes = %v, want both upgraded", ph)
	}
	if !eq(up.touched(), []string{"pn8", "vn0", "vn1"}) {
		t.Errorf("upgraded %v, want every node attempted", up.touched())
	}
	// Still not rolled back: nothing on it was displaced.
	if got := up.restored(); len(got) != 0 {
		t.Errorf("restored %v, want no rollback on an untouched node", got)
	}
}
