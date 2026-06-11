package wgeasy

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shidoh/wgfleet/internal/domain"
)

// newWGEasyDB creates a temp SQLite db with a minimal interfaces_table matching
// wg-easy's schema, optionally seeding an interface row.
func newWGEasyDB(t *testing.T, seedRow bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg-easy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE interfaces_table (
		name TEXT PRIMARY KEY,
		device TEXT NOT NULL DEFAULT 'eth0',
		port INTEGER NOT NULL DEFAULT 51820,
		private_key TEXT NOT NULL DEFAULT 'PRIV',
		public_key TEXT NOT NULL DEFAULT 'PUB',
		ipv4_cidr TEXT NOT NULL DEFAULT '10.80.0.0/24',
		ipv6_cidr TEXT NOT NULL DEFAULT 'fd00::/64',
		mtu INTEGER NOT NULL DEFAULT 1420,
		j_c INTEGER DEFAULT 7, j_min INTEGER DEFAULT 10, j_max INTEGER DEFAULT 1000,
		s1 INTEGER DEFAULT 128, s2 INTEGER DEFAULT 56, s3 INTEGER, s4 INTEGER,
		h1 TEXT, h2 TEXT, h3 TEXT, h4 TEXT,
		i1 TEXT, i2 TEXT, i3 TEXT, i4 TEXT, i5 TEXT,
		enabled INTEGER NOT NULL DEFAULT 1
	)`)
	if err != nil {
		t.Fatal(err)
	}
	if seedRow {
		if _, err := db.Exec(`INSERT INTO interfaces_table (name) VALUES ('wg0')`); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func sampleParams() domain.AWGParams {
	return domain.AWGParams{
		Shared: domain.AWGShared{
			H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
			H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
			H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
			H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
			S1: 102, S2: 67, S3: 143, S4: 38,
		},
		Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900},
	}
}

func TestColumnsFromParams(t *testing.T) {
	c := ColumnsFromParams(sampleParams())
	if c.H1 != "15384729-145384729" {
		t.Errorf("H1 = %q, want range string", c.H1)
	}
	if c.S1 != 102 || c.Jc != 5 {
		t.Errorf("S1/Jc mismatch: %+v", c)
	}
}

func TestUpdateAndReadAWG(t *testing.T) {
	ctx := context.Background()
	path := newWGEasyDB(t, true)
	cols := ColumnsFromParams(sampleParams())

	if err := UpdateAWG(ctx, path, "wg0", cols); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, found, err := ReadAWG(ctx, path, "wg0")
	if err != nil || !found {
		t.Fatalf("read: %v found=%v", err, found)
	}
	if got != cols {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, cols)
	}
}

func TestReadAWGNotFound(t *testing.T) {
	// Table exists but no interface row ⇒ found=false, no error.
	path := newWGEasyDB(t, false)
	_, found, err := ReadAWG(context.Background(), path, "wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false when interface row absent")
	}
}

func TestUpdateAWGMissingRow(t *testing.T) {
	path := newWGEasyDB(t, false)
	err := UpdateAWG(context.Background(), path, "wg0", ColumnsFromParams(sampleParams()))
	if err == nil {
		t.Fatal("expected error updating a non-existent interface")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

func TestUpdateDoesNotTouchKeysOrI(t *testing.T) {
	ctx := context.Background()
	path := newWGEasyDB(t, true)

	db, _ := sql.Open("sqlite", path)
	_, _ = db.Exec(`UPDATE interfaces_table SET private_key='KEEP', i1='operator-i1' WHERE name='wg0'`)
	_ = db.Close()

	if err := UpdateAWG(ctx, path, "wg0", ColumnsFromParams(sampleParams())); err != nil {
		t.Fatal(err)
	}

	db2, _ := sql.Open("sqlite", path)
	defer db2.Close()
	var priv, i1 string
	_ = db2.QueryRow(`SELECT private_key, COALESCE(i1,'') FROM interfaces_table WHERE name='wg0'`).Scan(&priv, &i1)
	if priv != "KEEP" {
		t.Errorf("private_key was modified: %q", priv)
	}
	if i1 != "operator-i1" {
		t.Errorf("i1 was modified: %q (must not touch per-end I values)", i1)
	}
}

func TestRenderUpdateSQL(t *testing.T) {
	sql := RenderUpdateSQL("wg0", ColumnsFromParams(sampleParams()))
	for _, want := range []string{"UPDATE interfaces_table", "j_c=5", "s1=102", "h1='15384729-145384729'", "WHERE name='wg0'"} {
		if !strings.Contains(sql, want) {
			t.Errorf("rendered SQL missing %q:\n%s", want, sql)
		}
	}
}
