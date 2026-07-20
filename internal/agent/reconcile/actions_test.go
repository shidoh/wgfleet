package reconcile

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A redactor declares the content secret-bearing. Redaction only affects the
// dry-run Display string — the real bytes hit the disk — so the mode is the only
// at-rest protection. Shipping 0644 alongside a redactor is how the master's
// mihomo config went out world-readable carrying one WireGuard private key per
// exit, and the master compose file carrying the wg-easy admin password.
func TestFileActionRefusesWorldReadableSecrets(t *testing.T) {
	redact := func(s string) string { return "REDACTED" }
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		_, err := FileAction(filepath.Join(t.TempDir(), "secret.yaml"), []byte("private-key: x"), mode, redact)
		if err == nil {
			t.Errorf("mode %#o with a redactor must be refused", mode)
		}
	}
	if _, err := FileAction(filepath.Join(t.TempDir(), "secret.yaml"), []byte("private-key: x"), 0o600, redact); err != nil {
		t.Errorf("0600 with a redactor must be allowed: %v", err)
	}
	// No redactor ⇒ not secret-bearing ⇒ a readable mode stays legal (nftables
	// rulesets, direct-networks lists and the like are deliberately world-readable).
	if _, err := FileAction(filepath.Join(t.TempDir(), "public.conf"), []byte("x"), 0o644, nil); err != nil {
		t.Errorf("0644 without a redactor must remain allowed: %v", err)
	}
}

// The mode is only applied on a write, so a file whose content is already current
// keeps whatever mode it has. That is how the master compose file sat at 0644
// holding the wg-easy admin password AFTER both the code fix and a manual chmod:
// the fix landed, the content never changed again, so nothing re-applied the mode.
func TestFileActionRepairsModeDriftWithoutRewriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.yaml")
	content := []byte("INIT_PASSWORD=hunter2\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	a, err := FileAction(path, content, 0o600, func(s string) string { return "REDACTED" })
	if err != nil {
		t.Fatal(err)
	}
	if !a.Changes() {
		t.Fatal("a world-readable secret with current content must still be a change")
	}
	if err := a.run(context.Background()); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}
	// A chmod, not a rewrite: churning mtime would trigger reloads on watched files.
	if !fi.ModTime().Equal(before.ModTime()) {
		t.Error("mode repair must not rewrite the file")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, content) {
		t.Error("content must be untouched")
	}
}

// A file that is already correct in both content and mode stays a no-change, or
// every reconcile pass would report drift forever.
func TestFileActionNoChangeWhenContentAndModeMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.yaml")
	content := []byte("x\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := FileAction(path, content, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Changes() {
		t.Fatalf("expected no-change, got %+v", a)
	}
}
