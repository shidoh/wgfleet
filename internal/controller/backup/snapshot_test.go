package backup

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSnapshotDBCopiesRows(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	db, err := sql.Open("sqlite", srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id TEXT); INSERT INTO t VALUES ('alpha');`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	dstPath := filepath.Join(dir, "snap.db")
	if err := SnapshotDB(context.Background(), srcPath, dstPath); err != nil {
		t.Fatalf("SnapshotDB: %v", err)
	}

	snap, err := sql.Open("sqlite", dstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var got string
	if err := snap.QueryRow(`SELECT id FROM t`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "alpha" {
		t.Fatalf("want alpha, got %q", got)
	}
}
