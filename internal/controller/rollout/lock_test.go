package rollout

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The Coordinator's in-memory Active flag guards ONE PROCESS. The serving
// controller and the --rolling-upgrade CLI are separate processes with separate
// state, so without a kernel-level lock both could drive the same exit's
// upload/verify/restart at once and, on failure, each roll back the other's work.
func TestRolloutLockIsExclusiveAcrossHolders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout.lock")

	first, err := acquireLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.release()

	if _, err := acquireLock(path); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second acquire = %v, want ErrLockHeld — the lock is not exclusive", err)
	}

	// Released locks are reusable, or a completed rollout would wedge the fleet.
	first.release()
	second, err := acquireLock(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	second.release()
}

// The lock file must not be world-readable and must be creatable under a fresh
// state dir (first run on a new controller).
func TestRolloutLockCreatesItsDirWithSaneMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "rollout.lock")
	l, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.release()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("lock mode = %o, want 0600", fi.Mode().Perm())
	}
}

// Tests disable locking with "-"; an empty path must mean the real default, so a
// missing config never silently drops fleet-wide exclusion.
func TestLockPathDefaultsToTheRealLock(t *testing.T) {
	if got := (Config{}).withDefaults().LockPath; got != DefaultLockPath {
		t.Fatalf("default LockPath = %q, want %q — an unset config must not disable locking", got, DefaultLockPath)
	}
}

func TestAcquireLockDisabledByEmptyPath(t *testing.T) {
	l, err := acquireLock("")
	if err != nil {
		t.Fatal(err)
	}
	l.release() // must be a safe no-op on the nil lock
}
