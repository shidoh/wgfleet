package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// A secret custom file must be writable at all.
//
// ManagedFileActions used to hand FileAction mode 0644 together with a redactor,
// and FileAction refuses exactly that pair — so `custom.files` with `secret: true`
// returned an error out of three planners and the node stopped converging on every
// pass, for good. The knob bricked the node it was configured on, and the only way
// to ship a secret file was to not mark it secret, which wrote it 0644 and printed
// it verbatim in plan output.
func TestManagedFileActionsWriteSecretsPrivately(t *testing.T) {
	dir := t.TempDir()
	files := []domain.ManagedFile{
		{Path: "public.conf", Content: "nothing to hide"},
		{Path: "private.conf", Content: "SUPERSECRET", Secret: true},
	}

	actions, err := ManagedFileActions(files, dir)
	if err != nil {
		t.Fatalf("ManagedFileActions() = %v, want a plan a node can actually apply", err)
	}
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(actions))
	}
	if got := actions[1].Display; strings.Contains(got, "SUPERSECRET") {
		t.Errorf("plan output leaks the secret file's content: %q", got)
	}

	for _, a := range actions {
		if a.apply == nil {
			continue
		}
		if err := a.apply(context.Background()); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	for _, tc := range []struct {
		name string
		want os.FileMode
	}{
		{"public.conf", 0o644},
		{"private.conf", 0o600},
	} {
		info, err := os.Stat(filepath.Join(dir, tc.name))
		if err != nil {
			t.Fatalf("stat %s: %v", tc.name, err)
		}
		if got := info.Mode().Perm(); got != tc.want {
			t.Errorf("%s mode = %#o, want %#o", tc.name, got, tc.want)
		}
	}
}
