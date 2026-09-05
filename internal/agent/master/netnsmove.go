package master

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Defaults for the move into mihomo's namespace. Asymmetric on purpose, the same
// asymmetry the tier selector uses and for the same reason: committing is cheap
// to get wrong because the way back is automatic, but giving up is expensive —
// a node that stops trying stays on the broken path until a human looks.
const (
	// moveConfirmPasses is how many consecutive passes must find the client path
	// healthy before the move is considered settled. Two rather than one: a single
	// pass immediately after the flip can catch the tunnel mid-rehandshake.
	moveConfirmPasses = 2
	// moveFailPasses is how many consecutive passes may find the client path broken
	// before the move is reverted. One is too eager — the flip itself disturbs
	// established flows — and three is a minute and a half of outage.
	moveFailPasses = 2
	// moveSettlePasses is how many passes after the flip are not judged at all.
	//
	// The flip is not one action, it is a pass. The compose planner recreates mihomo
	// into the namespace, the namespace planner arms the rules, the master NAT
	// disarms the host — and the client path is measured at the END of that same
	// pass, against a container Docker has just replaced and which may not have
	// bound its listeners yet. Measured on the stand 2026-09-05: every attempt
	// attached, failed its next two probes on exactly that, and reverted; three
	// attempts and the node gave up on a migration that was working.
	//
	// So the failure counter starts after the disturbance rather than during it.
	// This is not a grace period for a broken path: a path that is still broken when
	// it expires is reverted on the same two-pass rule as before.
	moveSettlePasses = 2
	// moveMaxAttempts is how many times a node may try before it stops. A node that
	// has failed this often is not going to succeed on the next pass either, and a
	// revert loop is worse than either state: clients would be moved and moved back
	// every minute, losing every connection each time.
	moveMaxAttempts = 3
	// moveRetryHold is how long a node waits after a revert before trying again. It
	// gates the FORWARD direction only. An earlier version used one hold for both,
	// and the arithmetic of that is worth stating: the flip that killed client
	// traffic instantly could not be undone for five minutes, three attempts came to
	// a quarter of an hour of outage, and the automatic revert — the entire reason
	// "on by default" was defensible — was slower than a human reading the alert.
	//
	// The asymmetry is the same one the tier selector uses, for the same reason:
	// committing is cheap to get wrong because the way back is automatic, so the way
	// back must never be rate-limited.
	moveRetryHold = 5 * time.Minute
)

// moveState is where a master is in the migration of client interception into
// mihomo's network namespace.
type moveState int

const (
	moveWaiting  moveState = iota // preconditions not met yet
	moveAttached                  // interception is in the namespace
	moveGaveUp                    // reverted too often; staying on the host path
)

// netnsMover decides, pass by pass, whether client traffic is intercepted inside
// mihomo's namespace.
//
// It exists because the migration is on by default, and "on by default" is only
// defensible with a way back that does not need a human. A switch nobody flips is
// a fix nobody gets; a switch that flips itself into an outage is worse than
// either. So the decision is: never move until the namespace demonstrably works,
// always move back if the client path stops working after moving, and stop trying
// after a few failures rather than oscillate.
//
// The revert is LOCAL by construction. The agent reaches its controller over the
// management overlay in the host namespace, which this migration does not touch,
// so going back needs nothing but this node.
//
// Not safe for concurrent use; the reconcile loop is single-threaded per pass.
// NetnsMove is the exported name of the decision machine; the agent owns one.
type NetnsMove = netnsMover

type netnsMover struct {
	state    moveState
	attempts int
	confirm  int
	fail     int
	settle   int
	lastFlip time.Time
	reason   string
	now      func() time.Time
	// statePath is where attempts and the terminal verdict survive a restart. Empty
	// ⇒ nothing is persisted, which is what tests want and what a --plan run must do.
	statePath string
}

// NewNetnsMove builds the decision machine, restoring what a previous process
// learned.
//
// Restoring matters more than it looks. The agent restarts on every upgrade and
// every reboot, and without this the attempt counter and the terminal "gave up"
// verdict went with it — so a node that had already reverted three times, been
// judged unfit and parked on the host path would come back up, forget all of it,
// and put its clients through the same three flips again. A safety mechanism that
// resets itself on the event most likely to follow a failure is not one.
func NewNetnsMove(statePath string) *NetnsMove {
	m := &netnsMover{now: time.Now, statePath: statePath}
	m.load()
	return m
}

func newNetnsMover() *netnsMover { return &netnsMover{now: time.Now} }

// Attached reports the current decision without taking a new one.
func (m *netnsMover) Attached() bool { return m.state == moveAttached }

// Reason explains the current state in one line, for the plan and the journal.
func (m *netnsMover) Reason() string { return m.reason }

// State names the current state for the metric. The strings are the label values
// and match metrics.NetnsMoveStates.
func (m *netnsMover) State() string {
	switch m.state {
	case moveAttached:
		return "attached"
	case moveGaveUp:
		return "gave_up"
	default:
		return "waiting"
	}
}

// Attempts is how many reverts this node has spent out of its allowance.
func (m *netnsMover) Attempts() int { return m.attempts }

// Decide advances the state machine for one pass.
//
//   - ready reports whether the namespace itself is fit to carry traffic (it can
//     resolve DNS and reach an exit). Checked BEFORE the first move and never
//     again: after the move the client path probe is the stronger question.
//   - pathOK reports whether the master's own client can still get traffic
//     through. Only consulted once attached; it is the thing that triggers the
//     revert.
//
// Both are functions rather than values so a pass that does not need them does
// not pay for them.
func (m *netnsMover) Decide(wanted bool, ready func() error, pathOK func() bool) bool {
	if !wanted {
		m.state, m.reason = moveWaiting, "disabled by master.client_via_netns"
		return false
	}
	switch m.state {
	case moveGaveUp:
		// Terminal until the agent restarts or the operator intervenes. Deliberate:
		// something about this node is wrong in a way retrying does not fix, and
		// moving clients back and forth every minute is not diagnosis.
		return false

	case moveWaiting:
		// The hold is checked BEFORE the readiness probe, and the order is not
		// cosmetic: ready() shells into the namespace and can take seconds, and
		// during the five minutes after a revert its answer is discarded anyway.
		// Ten wasted probes per hold window, each able to stretch a 30-second pass.
		if !m.retryHeld() {
			m.reason = "waiting out the retry hold before trying again"
			return false
		}
		if err := ready(); err != nil {
			m.reason = "waiting: " + err.Error()
			return false
		}
		m.state, m.confirm, m.fail = moveAttached, 0, 0
		m.settle = moveSettlePasses
		m.lastFlip = m.now()
		m.reason = "namespace ready; client interception moved in"
		return true

	case moveAttached:
		if m.settle > 0 {
			// Still inside the flip. Nothing is asked of the path yet, and nothing is
			// counted against it — the container carrying that path is being replaced.
			m.settle--
			m.reason = fmt.Sprintf("settling after the move (%d pass(es) to go)", m.settle)
			return true
		}
		if pathOK() {
			m.fail = 0
			if m.confirm < moveConfirmPasses {
				m.confirm++
				// A move that has held up for this long has earned its attempts back. The
				// counter exists to stop a node OSCILLATING, not to ration migrations over
				// the lifetime of a process: without this, three unrelated failures weeks
				// apart — a Docker Hub outage in March, a reboot in April — add up to a
				// terminal verdict about a node that has been fine in between. It also
				// gives moveConfirmPasses something to do; it used to be incremented,
				// printed and never read, while the comment promised the move was not
				// "settled" until it reached the threshold.
				if m.confirm == moveConfirmPasses && m.attempts > 0 {
					m.attempts = 0
					m.save()
				}
			}
			m.reason = fmt.Sprintf("client path healthy (%d/%d confirmations)", m.confirm, moveConfirmPasses)
			return true
		}
		m.fail++
		m.confirm = 0
		if m.fail < moveFailPasses {
			m.reason = fmt.Sprintf("client path failing (%d/%d before reverting)", m.fail, moveFailPasses)
			return true
		}
		// The revert is UNCONDITIONAL. No hold gates it: clients are on the floor, and
		// every second spent honouring a churn limit is a second of outage bought with
		// somebody else's traffic.
		m.attempts++
		m.lastFlip = m.now()
		m.fail = 0
		if m.attempts >= moveMaxAttempts {
			m.state = moveGaveUp
			m.reason = fmt.Sprintf("reverted %d times; staying on the host path until someone looks", m.attempts)
			m.save()
			return false
		}
		m.state = moveWaiting
		m.reason = fmt.Sprintf("client path broke after the move; reverted (attempt %d of %d)",
			m.attempts, moveMaxAttempts)
		m.save()
		return false
	}
	return false
}

// retryHeld reports whether the retry hold since the last flip has elapsed. It
// gates only the move FORWARD; the way back is never held. The first decision of
// a process is not held back either — a fresh agent must be able to act at once —
// except when a persisted flip says otherwise, which is how a restart loop is
// kept from becoming a flip loop.
func (m *netnsMover) retryHeld() bool {
	if m.lastFlip.IsZero() {
		return true
	}
	return m.now().Sub(m.lastFlip) >= moveRetryHold
}

// moveRecord is what survives a restart: the attempts spent and whether this node
// has been judged unfit. Deliberately NOT the attached/detached state — that is
// re-derived from the world every pass, and a file claiming the interception is
// somewhere it is not would be worse than no file.
type moveRecord struct {
	Attempts int       `json:"attempts"`
	GaveUp   bool      `json:"gave_up"`
	LastFlip time.Time `json:"last_flip"`
	Reason   string    `json:"reason"`
}

func (m *netnsMover) load() {
	if m.statePath == "" {
		return
	}
	b, err := os.ReadFile(m.statePath)
	if err != nil {
		return // no record is the normal first-boot case
	}
	var rec moveRecord
	if json.Unmarshal(b, &rec) != nil {
		return
	}
	m.attempts, m.lastFlip = rec.Attempts, rec.LastFlip
	if rec.GaveUp {
		m.state = moveGaveUp
		m.reason = "carried over from a previous run: " + rec.Reason
	}
}

// save records the counters. A failure to write is logged nowhere and fails
// nothing: the pass succeeded, and losing the safety net is not a reason to also
// lose the convergence. It is visible in the file's absence, which is what the
// runbook tells an operator to look at.
func (m *netnsMover) save() {
	if m.statePath == "" {
		return
	}
	b, err := json.Marshal(moveRecord{
		Attempts: m.attempts,
		GaveUp:   m.state == moveGaveUp,
		LastFlip: m.lastFlip,
		Reason:   m.reason,
	})
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.statePath), 0o700)
	_ = os.WriteFile(m.statePath, b, 0o600)
}
