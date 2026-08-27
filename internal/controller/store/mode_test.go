package store

import (
	"os"
	"path/filepath"
	"testing"
)

// The store holds every end user's WireGuard private key. SQLite creates its
// files 0644 by default, which on a shared host is every local account's copy of
// the client base — so the mode is enforced here rather than documented.
// The -wal and -shm siblings carry the same rows and get the same treatment.
func TestStoreFilesAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Force the WAL companions into existence with a real write.
	if err := s.SetAuthCredential(t.Context(), "admin", "hash", []byte("secret-secret-secret-secret-32b")); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if os.IsNotExist(err) {
			continue // -shm only exists while WAL is active on some platforms
		}
		if err != nil {
			t.Fatalf("stat %s: %v", filepath.Base(p), err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600 (it holds every client's private key)", filepath.Base(p), perm)
		}
	}
}

// Opening an existing store repairs a mode someone widened — a restore from a
// tarball, an rsync, a hand-edit. Enforcing only at creation would leave the
// invariant true exactly once.
func TestStoreRepairsAWidenedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode after reopen = %o, want 600 (a widened mode must be repaired)", perm)
	}
}
