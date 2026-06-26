package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func buildTestArchive(t *testing.T, dest string, wire int) []byte {
	t.Helper()
	items := []Item{{Name: "controller/state.db", Dest: dest, Mode: 0o600, Layer: LayerController, Data: []byte("NEWDB")}}
	m := Manifest{Schema: ArchiveSchema, WireVersion: wire, Layers: []Layer{LayerController}}
	for _, it := range items {
		m.Entries = append(m.Entries, Entry{Name: it.Name, Dest: it.Dest, Mode: uint32(it.Mode), Layer: it.Layer})
	}
	raw, err := BuildTar(m, items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRestoreApplyWritesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.db")
	if err := os.WriteFile(dest, []byte("OLDDB"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := buildTestArchive(t, dest, 7)
	identity := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }

	plan, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt: identity, WireVersion: 7, Plan: false,
		Now: func() time.Time { return time.Unix(1000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "NEWDB" {
		t.Fatalf("dest not restored: %q", got)
	}
	if len(plan.Writes) != 1 || plan.Writes[0].Backup == "" {
		t.Fatalf("expected a backup record: %+v", plan.Writes)
	}
	bak, _ := os.ReadFile(plan.Writes[0].Backup)
	if string(bak) != "OLDDB" {
		t.Fatalf("preflight backup missing old contents: %q", bak)
	}
}

func TestRestorePlanWritesNothing(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.db")
	_ = os.WriteFile(dest, []byte("OLDDB"), 0o600)
	archive := buildTestArchive(t, dest, 7)
	identity := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }

	if _, err := Restore(context.Background(), archive, RestoreOptions{Decrypt: identity, WireVersion: 7, Plan: true}); err != nil {
		t.Fatalf("Restore plan: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "OLDDB" {
		t.Fatalf("plan mode must not write; dest=%q", got)
	}
}

func TestRestoreRejectsNewerWire(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestArchive(t, filepath.Join(dir, "state.db"), 9)
	identity := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }
	if _, err := Restore(context.Background(), archive, RestoreOptions{Decrypt: identity, WireVersion: 7}); err == nil {
		t.Fatal("expected refusal restoring a newer-wire archive")
	}
}
