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

// settleOut drives the passes that follow a flip, during which the path is not
// judged: the container carrying it is being replaced.
func settleOut(m *netnsMover) {
	for range moveSettlePasses {
		m.Decide(true, isReady, pathUp)
	}
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
	settleOut(m)
	*clock = clock.Add(moveRetryHold + time.Second)

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
	settleOut(m)
	*clock = clock.Add(moveRetryHold + time.Second)

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
		settleOut(m)
		*clock = clock.Add(moveRetryHold + time.Second)
		for range moveFailPasses {
			m.Decide(true, isReady, pathDown)
		}
		*clock = clock.Add(moveRetryHold + time.Second)
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

// The hold gates the move FORWARD and nothing else. A revert cannot immediately
// be followed by another attempt.
func TestMoveHoldsBeforeTryingAgain(t *testing.T) {
	m, _ := testMover()
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move")
	}
	settleOut(m)
	for range moveFailPasses {
		m.Decide(true, isReady, pathDown)
	}
	if m.Attached() {
		t.Fatal("test premise: the path failed and it should have reverted")
	}
	// No clock advance: another attempt now would be churn.
	if m.Decide(true, isReady, pathUp) {
		t.Error("moved again immediately after reverting")
	}
	if !strings.Contains(m.Reason(), "hold") {
		t.Errorf("the reason does not mention the hold: %q", m.Reason())
	}
}

// The blocker: the hold used to gate the REVERT too, so a flip that killed client
// traffic instantly could not be undone for five minutes — three attempts came to
// a quarter of an hour of outage, and the automatic revert was slower than a human
// reading the alert.
func TestRevertIsNotHeldBack(t *testing.T) {
	m, _ := testMover()
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move")
	}
	// No clock advance at all: the flip has just happened, has settled, and has
	// just broken.
	settleOut(m)
	for range moveFailPasses {
		m.Decide(true, isReady, pathDown)
	}
	if m.Attached() {
		t.Fatalf("clients are on the floor and the revert is waiting out a churn limit: %q", m.Reason())
	}
}

// A move that has held up must earn its attempts back. The counter is there to
// stop a node oscillating, not to ration migrations over the life of a process:
// three unrelated failures weeks apart would otherwise add up to a terminal
// verdict about a node that has been fine in between.
func TestConfirmationsClearSpentAttempts(t *testing.T) {
	m, clock := testMover()
	m.Decide(true, isReady, pathUp)
	settleOut(m)
	for range moveFailPasses {
		m.Decide(true, isReady, pathDown)
	}
	if m.attempts != 1 {
		t.Fatalf("test premise: attempts = %d, want 1", m.attempts)
	}
	*clock = clock.Add(moveRetryHold + time.Second)
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move again after the hold")
	}
	settleOut(m)
	for range moveConfirmPasses {
		m.Decide(true, isReady, pathUp)
	}
	if m.attempts != 0 {
		t.Errorf("a settled move did not clear its spent attempts: %d", m.attempts)
	}
}

// The attempt counter and the terminal verdict must survive a restart — the agent
// restarts on every upgrade and every reboot, which is exactly when a node that
// has already been judged unfit would otherwise get a fresh set of three flips.
func TestGiveUpSurvivesARestart(t *testing.T) {
	path := t.TempDir() + "/netns-move.json"
	now := time.Now()
	m := NewNetnsMove(path)
	m.now = func() time.Time { return now }
	for attempt := 1; attempt <= moveMaxAttempts; attempt++ {
		m.Decide(true, isReady, pathUp)
		settleOut(m)
		for range moveFailPasses {
			m.Decide(true, isReady, pathDown)
		}
		now = now.Add(moveRetryHold + time.Second)
	}
	if m.Decide(true, isReady, pathUp) {
		t.Fatal("test premise: it should have given up by now")
	}

	restarted := NewNetnsMove(path)
	restarted.now = func() time.Time { return now.Add(time.Hour) }
	if restarted.Decide(true, isReady, pathUp) {
		t.Fatal("a restart handed a node that had already given up a fresh set of flips")
	}
	if !strings.Contains(restarted.Reason(), "previous run") {
		t.Errorf("the restored verdict does not say where it came from: %q", restarted.Reason())
	}
}

// No state path means no file: a --plan run must not write anything, and tests
// must not depend on a directory existing.
func TestMoveWithoutAStatePathWritesNothing(t *testing.T) {
	m, _ := testMover()
	m.Decide(true, isReady, pathUp)
	settleOut(m)
	for range moveFailPasses {
		m.Decide(true, isReady, pathDown)
	}
	// The assertion is simply that none of the above panicked or created anything;
	// statePath is empty, so save() is a no-op by construction.
	if m.statePath != "" {
		t.Fatal("the test mover acquired a state path")
	}
}

// The flip is a pass, not an action: compose recreates mihomo into the namespace,
// the namespace planner arms the rules, the master NAT disarms the host — and the
// client path is measured at the END of that same pass, against a container
// Docker has just replaced. Measured on the stand 2026-09-05: every attempt
// attached, failed its next two probes on exactly that, and reverted, until the
// node gave up on a migration that was working.
func TestMoveIsNotJudgedWhileItIsStillHappening(t *testing.T) {
	m, _ := testMover()
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move")
	}
	for i := range moveSettlePasses {
		if !m.Decide(true, isReady, pathDown) {
			t.Fatalf("reverted while the move was still settling (pass %d)", i+1)
		}
		if !strings.Contains(m.Reason(), "settling") {
			t.Errorf("the reason does not say it is settling: %q", m.Reason())
		}
	}
	// The grace is over; the ordinary rule applies again.
	if !m.Decide(true, isReady, pathDown) {
		t.Error("reverted on the first failing pass after settling")
	}
	if m.Decide(true, isReady, pathDown) {
		t.Fatal("a path that is still broken after settling must be reverted")
	}
}

// And the grace is not a way to hide a working path either: a healthy path
// confirms as before once the settle window has passed.
func TestSettlingDoesNotDelayConfirmationForever(t *testing.T) {
	m, _ := testMover()
	m.Decide(true, isReady, pathUp)
	for range moveSettlePasses {
		m.Decide(true, isReady, pathUp)
	}
	for range moveConfirmPasses {
		m.Decide(true, isReady, pathUp)
	}
	if !strings.Contains(m.Reason(), "confirmations") {
		t.Errorf("a settled, healthy move never reached confirmation: %q", m.Reason())
	}
}

// Turning the feature off and on again must try at once.
//
// The retry hold exists to stop a node oscillating on its own. An operator
// disabling the migration is not an oscillation, and neither is the flip that
// disabling undid — nothing failed. Left in place, the hold outlives the decision
// that caused it. Measured on the stand 2026-09-05: the knob went on and the node
// sat still for four minutes waiting out a hold for a flip it had been told to
// reverse.
func TestDisablingClearsTheHoldSoReEnablingIsImmediate(t *testing.T) {
	m, _ := testMover()
	if !m.Decide(true, isReady, pathUp) {
		t.Fatal("did not move")
	}
	// The operator turns it off — no clock advance at all.
	if m.Decide(false, isReady, pathUp) {
		t.Fatal("stayed attached while disabled")
	}
	// ...and straight back on.
	if !m.Decide(true, isReady, pathUp) {
		t.Fatalf("re-enabling waited out a hold for a flip the operator reversed: %q", m.Reason())
	}
}

// Disabling is also the documented way out of a terminal verdict: "staying on the
// host path until someone looks" — this is someone looking.
//
// Asserted THROUGH THE FILE, not just in memory. The first version of this test
// checked the machine and passed while the on-disk record still said `gave_up:
// true` — save() serialises the current state and was being called before the
// state was cleared. In memory the node was free; every agent restart put it back
// in the corner, which on the stand meant a node that could never move again.
func TestDisablingClearsATerminalVerdictOnDiskToo(t *testing.T) {
	path := t.TempDir() + "/netns-move.json"
	now := time.Now()
	m := NewNetnsMove(path)
	m.now = func() time.Time { return now }
	for range moveMaxAttempts {
		m.Decide(true, isReady, pathUp)
		settleOut(m)
		for range moveFailPasses {
			m.Decide(true, isReady, pathDown)
		}
		now = now.Add(moveRetryHold + time.Second)
	}
	if m.Decide(true, isReady, pathUp) {
		t.Fatal("test premise: it should have given up")
	}

	m.Decide(false, isReady, pathUp) // the operator intervenes

	// The machine that comes back after a restart is the one that matters.
	restarted := NewNetnsMove(path)
	restarted.now = func() time.Time { return now.Add(time.Hour) }
	if !restarted.Decide(true, isReady, pathUp) {
		t.Fatalf("a restart put the node back in the corner the operator freed it from: %q",
			restarted.Reason())
	}
	if restarted.Attempts() != 0 {
		t.Errorf("spent attempts survived on disk: %d", restarted.Attempts())
	}
}
