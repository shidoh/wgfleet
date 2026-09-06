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
		Local: domain.AWGLocal{
			Jc: 5, Jmin: 60, Jmax: 900,
			I1: "<b 0xc0ffee><r 12>", I2: "<b 0xdead><rd 8>", I3: "<rc 16>",
			I4: "<b 0xbeef><r 4>", I5: "<rd 20>",
		},
	}
}

func sampleSpec() domain.WGServerSpec {
	p := sampleParams()
	return domain.WGServerSpec{
		ListenPort:  443,
		AddressPool: "10.80.0.0/24",
		MTU:         1360,
		AWG:         &p,
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
	// AWG-only mapper leaves the transport columns zero.
	if c.Port != 0 || c.IPv4CIDR != "" || c.MTU != 0 {
		t.Errorf("ColumnsFromParams must not set transport fields: %+v", c)
	}
}

func TestColumnsFromSpec(t *testing.T) {
	c := ColumnsFromSpec(sampleSpec())
	if c.Port != 443 || c.IPv4CIDR != "10.80.0.0/24" || c.MTU != 1360 {
		t.Errorf("transport columns mismatch: %+v", c)
	}
	if c.S1 != 102 || c.Jc != 5 || c.H1 != "15384729-145384729" {
		t.Errorf("AWG columns mismatch: %+v", c)
	}
}

func TestUpdateAndReadInterface(t *testing.T) {
	ctx := context.Background()
	path := newWGEasyDB(t, true)
	cols := ColumnsFromSpec(sampleSpec())

	if err := UpdateInterface(ctx, path, "wg0", cols); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, found, err := ReadInterface(ctx, path, "wg0")
	if err != nil || !found {
		t.Fatalf("read: %v found=%v", err, found)
	}
	if got != cols {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, cols)
	}
}

func TestReadInterfaceNotFound(t *testing.T) {
	// Table exists but no interface row ⇒ found=false, no error.
	path := newWGEasyDB(t, false)
	_, found, err := ReadInterface(context.Background(), path, "wg0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("expected found=false when interface row absent")
	}
}

func TestUpdateInterfaceMissingRow(t *testing.T) {
	path := newWGEasyDB(t, false)
	err := UpdateInterface(context.Background(), path, "wg0", ColumnsFromSpec(sampleSpec()))
	if err == nil {
		t.Fatal("expected error updating a non-existent interface")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

// TestUpdateEnforcesTransport proves a persisted DB seeded with wg-easy defaults
// (port 51820, pool 10.80.0.0/24, mtu 1420) is reconciled to the desired spec —
// the bug where INIT_* are ignored on an existing DB so the configured client
// port never took effect.
func TestUpdateEnforcesTransport(t *testing.T) {
	ctx := context.Background()
	path := newWGEasyDB(t, true) // seeds port=51820, mtu=1420 (wg-easy defaults)

	if err := UpdateInterface(ctx, path, "wg0", ColumnsFromSpec(sampleSpec())); err != nil {
		t.Fatal(err)
	}
	got, _, err := ReadInterface(ctx, path, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 443 || got.MTU != 1360 {
		t.Errorf("transport not enforced: port=%d mtu=%d (want 443/1360)", got.Port, got.MTU)
	}
}

func TestUpdateDoesNotTouchKeys(t *testing.T) {
	ctx := context.Background()
	path := newWGEasyDB(t, true)

	db, _ := sql.Open("sqlite", path)
	_, _ = db.Exec(`UPDATE interfaces_table SET private_key='KEEP' WHERE name='wg0'`)
	_ = db.Close()

	if err := UpdateInterface(ctx, path, "wg0", ColumnsFromSpec(sampleSpec())); err != nil {
		t.Fatal(err)
	}

	db2, _ := sql.Open("sqlite", path)
	defer db2.Close()
	var priv, i1 string
	_ = db2.QueryRow(`SELECT private_key, COALESCE(i1,'') FROM interfaces_table WHERE name='wg0'`).Scan(&priv, &i1)
	if priv != "KEEP" {
		t.Errorf("private_key was modified: %q (wg-easy owns its identity)", priv)
	}
	// I1-I5 ARE now managed: the derived signature must be written, not left blank.
	if i1 != "<b 0xc0ffee><r 12>" {
		t.Errorf("i1 was not set to the derived signature: %q", i1)
	}
}

func TestRenderUpdateSQL(t *testing.T) {
	sql := RenderUpdateSQL("wg0", ColumnsFromSpec(sampleSpec()))
	for _, want := range []string{
		"UPDATE interfaces_table", "port=443", "ipv4_cidr='10.80.0.0/24'", "mtu=1360",
		"j_c=5", "s1=102", "s3=143", "s4=38", "h1='15384729-145384729'",
		"i1='<b 0xc0ffee><r 12>'", "WHERE name='wg0'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("rendered SQL missing %q:\n%s", want, sql)
		}
	}
}

// TestEmptyISlotsWriteNull pins the fix for the STUN+QUIC combo: with only I1/I2
// set and I3-I5 empty, the empty slots must be written as SQL NULL (wg-easy omits
// the line when regenerating wg0.conf), never as ” (which risks a malformed
// `Ix = ` that the AWG parser rejects, taking wg0 down).
func TestEmptyISlotsWriteNull(t *testing.T) {
	ctx := context.Background()
	path := newWGEasyDB(t, true)

	cols := ColumnsFromSpec(sampleSpec())
	cols.I1 = "<b 0x000100002112a442><r 12>"                        // STUN
	cols.I2 = "<b 0xc30000000108><r 8><b 0x08><r 8><b 0x00><r 120>" // QUIC
	cols.I3, cols.I4, cols.I5 = "", "", ""

	if err := UpdateInterface(ctx, path, "wg0", cols); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Raw check: i1/i2 hold their values, i3/i4/i5 are SQL NULL (not '').
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var i1, i2 string
	var i3Null, i4Null, i5Null bool
	err = db.QueryRow(`SELECT COALESCE(i1,''), COALESCE(i2,''),
		i3 IS NULL, i4 IS NULL, i5 IS NULL FROM interfaces_table WHERE name='wg0'`).
		Scan(&i1, &i2, &i3Null, &i4Null, &i5Null)
	if err != nil {
		t.Fatal(err)
	}
	if i1 != cols.I1 || i2 != cols.I2 {
		t.Errorf("i1/i2 not written: i1=%q i2=%q", i1, i2)
	}
	if !i3Null || !i4Null || !i5Null {
		t.Errorf("empty I-slots must be SQL NULL, got i3Null=%v i4Null=%v i5Null=%v", i3Null, i4Null, i5Null)
	}

	// The dry-run rendering must match: empty slots as NULL, set ones quoted.
	sqlText := RenderUpdateSQL("wg0", cols)
	for _, want := range []string{"i3=NULL", "i4=NULL", "i5=NULL", "i1='<b 0x000100002112a442><r 12>'"} {
		if !strings.Contains(sqlText, want) {
			t.Errorf("rendered SQL missing %q:\n%s", want, sqlText)
		}
	}
}
