package master

import (
	"fmt"
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
	// moveMaxAttempts is how many times a node may try before it stops. A node that
	// has failed this often is not going to succeed on the next pass either, and a
	// revert loop is worse than either state: clients would be moved and moved back
	// every minute, losing every connection each time.
	moveMaxAttempts = 3
	// moveMinHold is the floor on churn between decisions.
	moveMinHold = 5 * time.Minute
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
	lastFlip time.Time
	reason   string
	now      func() time.Time
}

// NewNetnsMove builds the decision machine in its initial state: waiting, with
// no attempts spent.
func NewNetnsMove() *NetnsMove { return &netnsMover{now: time.Now} }

func newNetnsMover() *netnsMover { return NewNetnsMove() }

// Attached reports the current decision without taking a new one.
func (m *netnsMover) Attached() bool { return m.state == moveAttached }

// Reason explains the current state in one line, for the plan and the journal.
func (m *netnsMover) Reason() string { return m.reason }

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
		if !m.held() {
			m.reason = "waiting out the min-hold before trying again"
			return false
		}
		if err := ready(); err != nil {
			m.reason = "waiting: " + err.Error()
			return false
		}
		m.state, m.confirm, m.fail = moveAttached, 0, 0
		m.lastFlip = m.now()
		m.reason = "namespace ready; client interception moved in"
		return true

	case moveAttached:
		if pathOK() {
			m.fail = 0
			if m.confirm < moveConfirmPasses {
				m.confirm++
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
		if !m.held() {
			m.reason = "client path failing; revert suppressed by min-hold"
			return true
		}
		m.attempts++
		m.lastFlip = m.now()
		m.fail = 0
		if m.attempts >= moveMaxAttempts {
			m.state = moveGaveUp
			m.reason = fmt.Sprintf("reverted %d times; staying on the host path until someone looks", m.attempts)
			return false
		}
		m.state = moveWaiting
		m.reason = fmt.Sprintf("client path broke after the move; reverted (attempt %d of %d)",
			m.attempts, moveMaxAttempts)
		return false
	}
	return false
}

// held reports whether the minimum hold since the last flip has elapsed. The
// first decision of a process is never held back — a fresh agent must be able to
// act at once.
func (m *netnsMover) held() bool {
	if m.lastFlip.IsZero() {
		return true
	}
	return m.now().Sub(m.lastFlip) >= moveMinHold
}
