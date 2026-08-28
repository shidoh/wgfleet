package main

import (
	"context"
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shidoh/wgfleet/internal/controller/backup"
)

func seedSQLite(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE nodes (id TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
}

func TestRunBackupRestoreRoundTripCLI(t *testing.T) {
	dir := t.TempDir()
	// Seed a controller layer.
	storePath := filepath.Join(dir, "state.db")
	seedSQLite(t, storePath)
	cfgPath := filepath.Join(dir, "controller.yaml")
	_ = os.WriteFile(cfgPath, []byte("controller: {}\n"), 0o600)
	caCert := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(caCert, []byte("CERT"), 0o600)

	// A master layer, seeded in the temp dir, so the round-trip exercises both
	// layers hermetically. Sources are passed explicitly rather than via
	// DefaultSources, whose fixed /etc/wgfleet/* master paths would otherwise make
	// this test read host files — and fail on a live node where e.g. wg.key exists
	// but is root-only (os.Stat succeeds, os.ReadFile is denied).
	wgKey := filepath.Join(dir, "wg.key")
	_ = os.WriteFile(wgKey, []byte("PRIVKEY"), 0o600)
	nodeCert := filepath.Join(dir, "node.crt")
	_ = os.WriteFile(nodeCert, []byte("NODECERT"), 0o600)

	src := backup.Sources{
		ControllerYAML: cfgPath,
		StateDB:        storePath,
		CACert:         caCert,
		WGKey:          wgKey,
		NodeCert:       nodeCert,
	}

	out := filepath.Join(dir, "backup.tar.age")
	identityEnc := func(_ context.Context, p []byte) ([]byte, error) { return p, nil }
	if err := runBackup(src, out, "", identityEnc); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() == 0 {
		t.Fatalf("archive not written: %v", err)
	}

	identityDec := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }
	plan, err := runRestore(context.Background(), out, true /*plan*/, identityDec, "", 99, "", nil)
	if err != nil {
		t.Fatalf("runRestore plan: %v", err)
	}
	if len(plan.Writes) == 0 {
		t.Fatal("expected restore plan to list writes")
	}
}

func TestRunRestoreRefusesLiveController(t *testing.T) {
	// A listener standing in for a running controller.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dir := t.TempDir()
	out := filepath.Join(dir, "backup.tar.age")
	_ = os.WriteFile(out, []byte("unused"), 0o600)
	dec := func(_ context.Context, c []byte) ([]byte, error) { return c, nil }

	// Apply mode (plan=false) must refuse while the address accepts connections.
	if _, err := runRestore(context.Background(), out, false, dec, "", 99, ln.Addr().String(), nil); err == nil {
		t.Fatal("expected apply-mode restore to refuse a live controller")
	}
}
