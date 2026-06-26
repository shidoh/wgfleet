package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestExportProducesParseableArchive(t *testing.T) {
	dir := t.TempDir()
	// Minimal live db.
	dbPath := filepath.Join(dir, "state.db")
	db, _ := sql.Open("sqlite", dbPath)
	_, _ = db.Exec(`CREATE TABLE nodes (id TEXT); INSERT INTO nodes VALUES ('n1');`)
	_ = db.Close()

	w := func(name string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(name), 0o600)
		return p
	}
	src := Sources{
		ControllerYAML: w("controller.yaml"),
		StateDB:        dbPath,
		CACert:         w("ca.crt"),
		CAKey:          w("ca.key"),
	}
	identity := func(_ context.Context, p []byte) ([]byte, error) { return p, nil } // no real encryption in test

	raw, err := Export(context.Background(), ExportOptions{
		Sources:     src,
		WireVersion: 7,
		Now:         func() time.Time { return time.Unix(0, 0).UTC() },
		Encrypt:     identity,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	m, items, err := ParseTar(raw)
	if err != nil {
		t.Fatalf("ParseTar: %v", err)
	}
	if m.WireVersion != 7 || len(m.Layers) != 1 {
		t.Fatalf("manifest: %+v", m)
	}
	var stateDB []byte
	for _, it := range items {
		if it.Name == "controller/state.db" {
			stateDB = it.Data
		}
	}
	if stateDB == nil {
		t.Fatal("state.db not captured")
	}
	// The snapshot must be a real, openable sqlite db with our row.
	snapPath := filepath.Join(dir, "verify.db")
	_ = os.WriteFile(snapPath, stateDB, 0o600)
	vdb, _ := sql.Open("sqlite", snapPath)
	defer vdb.Close()
	var id string
	if err := vdb.QueryRow(`SELECT id FROM nodes`).Scan(&id); err != nil || id != "n1" {
		t.Fatalf("snapshot row mismatch: id=%q err=%v", id, err)
	}
}
