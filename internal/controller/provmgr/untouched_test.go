package provmgr

import (
	"errors"
	"testing"
)

// untouched mirrors how the rollout coordinator inspects the error: structurally,
// without importing this package.
func untouched(err error) bool {
	var u interface{ NodeUntouched() bool }
	return errors.As(err, &u) && u.NodeUntouched()
}

// TestUntouchedErrorIsRecognisedStructurally pins the contract the coordinator
// relies on. If this type ever stops satisfying the behaviour — renamed method,
// value/pointer receiver change, a wrapper that drops Unwrap — the coordinator
// silently goes back to rolling back nodes it never reached — and downgrading
// healthy ones to a stale snapshot.
func TestUntouchedErrorIsRecognisedStructurally(t *testing.T) {
	if !untouched(untouchedf("ssh dial %q: %v", "pn8", errors.New("i/o timeout"))) {
		t.Error("untouchedf must produce an error the coordinator recognises")
	}
	if !untouched(untouchedError{errors.New("busy")}) {
		t.Error("untouchedError must satisfy the behaviour directly")
	}
}

// TestUntouchedErrorUnwrapsAndKeepsItsMessage — the tag must not hide the cause:
// it is what the operator reads in the rollout UI and the CLI log.
func TestUntouchedErrorUnwrapsAndKeepsItsMessage(t *testing.T) {
	cause := errors.New("i/o timeout")
	err := untouchedf("ssh dial %q: %w", "pn8", cause)
	if !errors.Is(err, cause) {
		t.Error("the wrapped cause must stay reachable via errors.Is")
	}
	if got, want := err.Error(), `ssh dial "pn8": i/o timeout`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestPlainErrorIsNotUntouched — the guard must stay narrow. A failure at or after
// the upload DID displace the binary, and if it were tagged the node would be
// stranded on the build that just failed.
func TestPlainErrorIsNotUntouched(t *testing.T) {
	if untouched(errors.New("sha256 mismatch after upload")) {
		t.Error("an ordinary error must not read as untouched")
	}
}
