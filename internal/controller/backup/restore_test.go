package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// The archive says where each item goes, and the archive is untrusted input:
// `age -r` does not authenticate a sender, so anyone holding the public key can
// build one. Restore used to read Dest straight from its manifest — an arbitrary
// root-owned write on the control-plane host.
func TestRestoreRefusesADestinationThisHostDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	legit := filepath.Join(dir, "state.db")
	evil := filepath.Join(dir, "authorized_keys")
	archive := buildTestArchive(t, evil, 99)
	identity := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }

	_, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt: identity, WireVersion: 99,
		AllowedDests: map[string]bool{filepath.Clean(legit): true},
	})
	if err == nil {
		t.Fatal("an archive wrote outside the set of places this host keeps files")
	}
	if !strings.Contains(err.Error(), "not a place this host keeps anything") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
	if _, serr := os.Stat(evil); serr == nil {
		t.Error("the refused destination was written anyway")
	}
}

// And an archive naming only places this host does own restores normally.
func TestRestoreAcceptsThisHostsOwnDestinations(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.db")
	archive := buildTestArchive(t, dest, 99)
	identity := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }

	if _, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt: identity, WireVersion: 99,
		AllowedDests: map[string]bool{filepath.Clean(dest): true},
	}); err != nil {
		t.Fatalf("a legitimate restore was refused: %v", err)
	}
	if b, err := os.ReadFile(dest); err != nil || string(b) != "NEWDB" {
		t.Errorf("restore did not write the file: %v %q", err, b)
	}
}

// A rejected item must not leave a half-restored host. The check used to live inside
// the write loop, so an archive whose fourth entry was refused had already moved
// three files aside and replaced them — on a box with the controller stopped and no
// rollback. A hostile archive got every write ahead of its bad entry for free; a
// merely wrong one did the same damage for a typo in a path.
func TestRestoreValidatesEveryDestinationBeforeWritingAny(t *testing.T) {
	dir := t.TempDir()
	legit := filepath.Join(dir, "controller.yaml")
	if err := os.WriteFile(legit, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "elsewhere", "authorized_keys")

	archive := tarOf(t,
		Item{Name: "controller/controller.yaml", Dest: legit, Mode: 0o644, Data: []byte("replacement")},
		Item{Name: "controller/evil", Dest: outside, Mode: 0o600, Data: []byte("ssh-rsa AAAA")},
	)
	_, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt:      func(context.Context, []byte) ([]byte, error) { return archive, nil },
		WireVersion:  1,
		AllowedDests: map[string]bool{absClean(legit): true},
	})
	if err == nil {
		t.Fatal("an archive naming a destination this host does not own was accepted")
	}
	if got, _ := os.ReadFile(legit); string(got) != "original" {
		t.Errorf("the legitimate file was already replaced before the refusal: %q", got)
	}
	entries, _ := filepath.Glob(legit + ".bak-*")
	if len(entries) != 0 {
		t.Errorf("the refusal left %d backup file(s) behind", len(entries))
	}
	if _, err := os.Stat(outside); err == nil {
		t.Error("the refused destination was written anyway")
	}
}

// The mode is the same untrusted field the destination was, and closing one while
// leaving the other open is not a fix: an archive naming this host's own ca.key with
// Mode 0644 passed the allow-list and made the fleet CA private key world-readable.
func TestRestoreTakesFileModesFromTheHostNotTheArchive(t *testing.T) {
	dir := t.TempDir()
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")

	archive := tarOf(t,
		Item{Name: "controller/ca.key", Dest: caKey, Mode: 0o644, Data: []byte("KEY")},
		Item{Name: "controller/ca.crt", Dest: caCert, Mode: 0o600, Data: []byte("CERT")},
	)
	if _, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt:     func(context.Context, []byte) ([]byte, error) { return archive, nil },
		WireVersion: 1,
		AllowedDests: map[string]bool{
			absClean(caKey): true, absClean(caCert): true,
		},
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	info, err := os.Stat(caKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("ca.key restored as %04o; the archive asked for 0644 and was believed", got)
	}
	certInfo, err := os.Stat(caCert)
	if err != nil {
		t.Fatal(err)
	}
	if got := certInfo.Mode().Perm(); got != 0o644 {
		t.Errorf("ca.crt restored as %04o, want 0644 — a public certificate is not a secret", got)
	}
}

// The only restore anybody performs is onto a host that did not shut down cleanly,
// which is exactly the case where SQLite's write-ahead log survives beside the
// database. Left in place, it belongs to the generation of the file we just replaced.
func TestRestoreRemovesTheStaleWriteAheadLog(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "state.db")
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		if err := os.WriteFile(p, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := tarOf(t, Item{Name: "controller/state.db", Dest: db, Mode: 0o600, Data: []byte("restored")})
	if _, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt:      func(context.Context, []byte) ([]byte, error) { return archive, nil },
		WireVersion:  1,
		AllowedDests: map[string]bool{absClean(db): true},
	}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(db + suffix); err == nil {
			t.Errorf("a stale %s survived beside the restored database", suffix)
		}
	}
}

// The archive names absolute paths; the allow-list is built from whatever -config the
// operator typed. `cd /etc/wgfleet && --config controller.yaml --restore …` used to
// refuse itself.
func TestRestoreAcceptsARelativelyConfiguredDestination(t *testing.T) {
	// EvalSymlinks because on macOS t.TempDir() hands back a /var path that Getwd
	// resolves to /private/var — a difference between the two sides of the comparison
	// that has nothing to do with what is being tested.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "controller.yaml")
	archive := tarOf(t, Item{Name: "controller/controller.yaml", Dest: dest, Mode: 0o644, Data: []byte("y")})

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	if _, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt:      func(context.Context, []byte) ([]byte, error) { return archive, nil },
		WireVersion:  1,
		AllowedDests: AllowedDestsFor(Sources{ControllerYAML: "controller.yaml"}),
	}); err != nil {
		t.Fatalf("a restore configured with a relative -config refused itself: %v", err)
	}
}

// tarOf builds an unencrypted archive holding exactly these items.
func tarOf(t *testing.T, items ...Item) []byte {
	t.Helper()
	m := Manifest{Schema: ArchiveSchema, WireVersion: 1, Layers: []Layer{LayerController}}
	for _, it := range items {
		m.Entries = append(m.Entries, Entry{Name: it.Name, Dest: it.Dest, Mode: uint32(it.Mode), Layer: LayerController})
	}
	raw, err := BuildTar(m, items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Archives made before wg-easy was dropped carry its database and admin password.
// Their destinations are no longer places this host keeps anything, so refusing
// them would refuse the whole archive: restore skips them and says so.
func TestRestoreSkipsRetiredWGEasyItems(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.db")
	retired := filepath.Join(dir, "wg-easy.db")
	items := []Item{
		{Name: "controller/state.db", Dest: dest, Mode: 0o600, Layer: LayerController, Data: []byte("NEWDB")},
		{Name: "master/wg-easy.db", Dest: retired, Mode: 0o600, Layer: LayerMaster, Data: []byte("OLD")},
	}
	m := Manifest{Schema: ArchiveSchema, WireVersion: 7, Layers: []Layer{LayerController, LayerMaster}}
	for _, it := range items {
		m.Entries = append(m.Entries, Entry{Name: it.Name, Dest: it.Dest, Mode: uint32(it.Mode), Layer: it.Layer})
	}
	archive, err := BuildTar(m, items)
	if err != nil {
		t.Fatal(err)
	}
	identity := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }

	plan, err := Restore(context.Background(), archive, RestoreOptions{
		Decrypt: identity, WireVersion: 7,
		AllowedDests: map[string]bool{filepath.Clean(dest): true},
	})
	if err != nil {
		t.Fatalf("an archive with a retired wg-easy item was refused: %v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "NEWDB" {
		t.Errorf("the rest of the archive was not restored: %q", b)
	}
	if _, err := os.Stat(retired); err == nil {
		t.Error("the retired wg-easy database was written")
	}
	if !strings.Contains(strings.Join(plan.Warnings, "\n"), "master/wg-easy.db") {
		t.Errorf("the skip is not reported: %v", plan.Warnings)
	}
}
