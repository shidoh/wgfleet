package master

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testMover() (*netnsMover, *time.Time) {
	now := time.Now()
	m := newNetnsMover()
	m.now = func() time.Time { return now }
	return m, &now
}

var (
	notReady = func() error { return errors.New("namespace cannot resolve DNS") }
	isReady  = func() error { return nil }
	pathUp   = func() bool { return true }
	pathDown = func() bool { return false }
)

// Nothing moves until the namespace has demonstrated it works. "On by default" is
// only defensible if the default cannot fire into a namespace that has no DNS and
// no route to an exit.
func TestMoveWaitsForTheNamespaceToBeReady(t *testing.T) {
	m, _ := testMover()
	if m.Decide(true, notReady, pathUp) {
		t.Fatal("moved into a namespace that is not ready")
	}
	if !strings.Contains(m.Reason(), "cannot resolve") {
		t.Errorf("the reason does not say what is missing: %q", m.Reason())
	}
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move once the namespace was ready")
	}
}

// A client path that breaks after the move must bring it back WITHOUT a human.
// The revert is local — the agent talks to its controller over the management
// overlay, which this migration does not touch — so nothing about it depends on
// the control plane being reachable.
func TestMoveRevertsItselfWhenTheClientPathBreaks(t *testing.T) {
	m, clock := testMover()
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move")
	}
	*clock = clock.Add(moveMinHold + time.Second)

	// One bad pass is tolerated: the flip itself disturbs established flows.
	if !m.Decide(true, isReady, pathDown) {
		t.Error("reverted on the first failing pass, before the path could settle")
	}
	if m.Decide(true, isReady, pathDown) {
		t.Fatal("stayed attached with the client path down")
	}
	if !strings.Contains(m.Reason(), "reverted") {
		t.Errorf("the reason does not say it reverted: %q", m.Reason())
	}
}

// A healthy path resets the failure count: an isolated bad pass must not
// accumulate towards a revert over hours.
func TestMoveForgetsAnIsolatedFailure(t *testing.T) {
	m, clock := testMover()
	m.Decide(true, isReady, pathUp)
	*clock = clock.Add(moveMinHold + time.Second)

	m.Decide(true, isReady, pathDown) // one bad
	m.Decide(true, isReady, pathUp)   // recovered
	if !m.Decide(true, isReady, pathDown) {
		t.Error("a single bad pass after recovery triggered a revert")
	}
}

// After enough failures the node stops trying. Moving clients in and out every
// few minutes is not diagnosis: each flip costs every established connection.
func TestMoveGivesUpRatherThanOscillate(t *testing.T) {
	m, clock := testMover()
	for attempt := 1; attempt <= moveMaxAttempts; attempt++ {
		if !m.Decide(true, isReady, pathUp) && attempt < moveMaxAttempts {
			t.Fatalf("attempt %d: did not move", attempt)
		}
		*clock = clock.Add(moveMinHold + time.Second)
		for range moveFailPasses {
			m.Decide(true, isReady, pathDown)
		}
		*clock = clock.Add(moveMinHold + time.Second)
	}
	if m.Decide(true, isReady, pathUp) {
		t.Fatal("kept trying after the attempt limit")
	}
	if !strings.Contains(m.Reason(), "staying on the host path") {
		t.Errorf("the terminal reason does not say what the node is doing now: %q", m.Reason())
	}
	// And it stays given up even when everything looks fine again.
	if m.Decide(true, isReady, pathUp) {
		t.Error("came back on its own after giving up")
	}
}

// "off" is inert and must not even ask the namespace whether it is ready.
func TestMoveRespectsOff(t *testing.T) {
	m, _ := testMover()
	if m.Decide(false, func() error { t.Fatal("probed while disabled"); return nil }, pathUp) {
		t.Fatal("moved while disabled")
	}
}

// Churn floor: a revert cannot immediately be followed by another move.
func TestMoveHoldsBetweenFlips(t *testing.T) {
	m, _ := testMover()
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move")
	}
	// No clock advance: the next decision is inside the hold window.
	for range moveFailPasses {
		m.Decide(true, isReady, pathDown)
	}
	if !m.Attached() {
		t.Error("reverted inside the minimum hold window")
	}
	if !strings.Contains(m.Reason(), "min-hold") {
		t.Errorf("the reason does not mention the hold: %q", m.Reason())
	}
}
