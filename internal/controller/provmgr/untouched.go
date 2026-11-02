package provmgr

import "fmt"

// untouchedError marks an upgrade failure that happened BEFORE anything on the
// node was modified: no binary uploaded, no rollback snapshot taken in this
// attempt, no service restarted.
//
// The rollout coordinator reads it structurally (an `interface{ NodeUntouched()
// bool }`), not by importing this package, so the dependency stays one-way — it
// declares the Upgrader interface, we implement it.
//
// It matters because a rollback restores `.prev`, and `.prev` is not a safety net
// belonging to the current attempt — it is whatever some EARLIER upgrade
// displaced, potentially weeks ago. Rolling back an attempt that never reached the
// node therefore does not undo anything; it overwrites a healthy binary with a
// stale one: after an SSH dial timeout, a node running the current wire version
// would come back on whatever older build the snapshot holds.
type untouchedError struct{ err error }

func (e untouchedError) Error() string     { return e.err.Error() }
func (e untouchedError) Unwrap() error     { return e.err }
func (untouchedError) NodeUntouched() bool { return true }

// untouchedf builds an untouchedError from a printf-style message. Use it for
// every failure path that returns before the first step that writes to the node.
func untouchedf(format string, a ...any) error {
	return untouchedError{fmt.Errorf(format, a...)}
}
