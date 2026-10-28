package reconcile

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A redactor declares the content secret-bearing. Redaction only affects the
// dry-run Display string — the real bytes hit the disk — so the mode is the only
// at-rest protection. Shipping 0644 alongside a redactor is how the master's
// mihomo config went out world-readable carrying one WireGuard private key per
// exit, and the master compose file carrying a container admin password.
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
// holding a container admin password AFTER both the code fix and a manual chmod:
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

// A plan is a snapshot, and by the time an action runs the world may no longer be
// the one that justified it. OnlyIf is how an action asks again.
//
// The case it was written for: the rule that sends clients into mihomo's namespace
// is preceded by the two best-effort commands that fill the table it points at. A
// best-effort failure is logged and the pass continues — so without a second look,
// the rule gets installed over a table nothing filled, and a rule pointing at an
// empty table does not fail. It routes every client out of the uplink.
func TestAnActionAsksAgainBeforeItActs(t *testing.T) {
	ran := false
	act := CustomAction(ActionExec, "target", "do the thing", "cmd",
		func(context.Context) error { ran = true; return nil })

	skipped := act.OnlyIf("the world moved", func(context.Context) bool { return false })
	err := skipped.run(context.Background())
	if ran {
		t.Fatal("the action ran although its precondition no longer held")
	}
	if err == nil || !strings.Contains(err.Error(), "the world moved") {
		t.Fatalf("a skip must say why, got %v", err)
	}

	ran = false
	allowed := act.OnlyIf("the world moved", func(context.Context) bool { return true })
	if err := allowed.run(context.Background()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !ran {
		t.Fatal("the action did not run although its precondition held")
	}
}

// And under BestEffort the skip must be a warning, not a failed pass: this runs on
// the master ahead of half its planners.
func TestASkippedActionDoesNotFailThePass(t *testing.T) {
	act := CustomAction(ActionExec, "target", "do the thing", "cmd",
		func(context.Context) error { return nil }).
		OnlyIf("not yet", func(context.Context) bool { return false }).
		BestEffort()
	if err := act.run(context.Background()); err != nil {
		t.Fatalf("a skipped best-effort action failed the pass: %v", err)
	}
}
