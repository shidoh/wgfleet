package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

// A reader must never see a half-written file, and the file that was there before
// must survive a write that fails.
func TestAFailedWriteLeavesThePreviousContentInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := Write(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory that cannot hold a temp file: the write must fail before the
	// rename, not halfway through the target.
	if err := Write(filepath.Join(dir, "nope", "key"), []byte("second\n"), 0o600); err == nil {
		t.Fatal("a write into a directory that does not exist reported success")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "first\n" {
		t.Fatalf("the previous content did not survive: %q %v", got, err)
	}
}

// The mode is the caller's, not the umask's: these files are keys.
func TestTheModeIsTheOneAskedFor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := Write(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode is %v, want 0600: a private key is readable by somebody else", fi.Mode().Perm())
	}
}

// No temporary files are left behind, successful or not: they hold the same secret
// as the target and would sit in the same directory forever.
func TestNoTemporaryFileSurvives(t *testing.T) {
	dir := t.TempDir()
	if err := Write(filepath.Join(dir, "key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "key" {
			t.Errorf("a temporary file holding the same secret was left behind: %s", e.Name())
		}
	}
}

// A rename is not durable until the DIRECTORY that now names the file is synced.
// Syncing the file alone survives a process crash but not a power cut: the bytes
// are on the platter and the directory entry pointing at them may not be, so the
// node comes back with the OLD identity — or none. The file sync was already here
// and read as if it covered this; it does not.
func TestTheDirectoryIsSyncedAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	var synced []string
	restore := syncDir
	syncDir = func(d string) error {
		synced = append(synced, d)
		return restore(d)
	}
	t.Cleanup(func() { syncDir = restore })

	if err := Write(filepath.Join(dir, "key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("the directory holding the file was not synced after the rename: %v", synced)
	}
}

// A directory that cannot be synced means the rename may not survive a power cut,
// and this file is a node's identity: say so rather than report a durable write.
func TestAFailedDirectorySyncIsReported(t *testing.T) {
	restore := syncDir
	syncDir = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { syncDir = restore })

	err := Write(filepath.Join(t.TempDir(), "key"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("a write whose directory could not be synced reported success")
	}
}
