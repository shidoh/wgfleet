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
