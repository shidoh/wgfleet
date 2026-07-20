package rollout

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// DefaultLockPath is where the cross-process rollout lock lives. It sits beside
// the store rather than in /tmp so it shares the store's lifetime and permissions.
const DefaultLockPath = "/var/lib/wgfleet/rollout.lock"

// procLock is an advisory whole-file lock (flock) held for the duration of a
// rollout.
//
// The Coordinator's own in-memory guard makes exactly one rollout run PER
// PROCESS, and that was mistaken for fleet-wide exclusion. It is not: the serving
// controller and `--rolling-upgrade` are separate processes, each building its own
// provmgr.Manager and Coordinator, so neither the coordinator's Active flag nor
// provmgr's per-node `inflight` map — both plain in-memory state — spans them.
// Two rollouts could therefore select the same exit and drive its upload/verify/
// restart sequence concurrently, and on failure each could read the other's
// actions as its own and fire a rollback, flapping the agent binary on a node.
//
// flock is the right primitive here: the kernel releases it when the holding
// process dies, so a crashed or SIGKILLed rollout cannot wedge the fleet behind a
// stale lock the way a database row or a PID file would.
type procLock struct{ f *os.File }

// ErrLockHeld reports that another process is already running a rollout.
var ErrLockHeld = errors.New("another process is already running a rolling upgrade")

// acquireLock takes the rollout lock without blocking. It returns ErrLockHeld
// when another process holds it, so the caller can refuse loudly instead of
// queueing behind work it cannot see.
func acquireLock(path string) (*procLock, error) {
	if path == "" {
		return nil, nil // locking disabled (tests)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("rollout lock: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("rollout lock: open %q: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLockHeld
		}
		return nil, fmt.Errorf("rollout lock: flock %q: %w", path, err)
	}
	// Best-effort breadcrumb for an operator who finds the lock held and wants to
	// know by whom. Never read back programmatically — the flock is the authority.
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "pid %d\n", os.Getpid())
	return &procLock{f: f}, nil
}

// release drops the lock. Safe on a nil lock so callers need no nil checks.
func (l *procLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
