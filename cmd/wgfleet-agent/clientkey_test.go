package main

import (
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func quietAgent(t *testing.T) *agent {
	t.Helper()
	return &agent{
		stateDir: t.TempDir(),
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// wgEasyDBWithoutAKey creates a database file shaped like wg-easy's but with no
// column the reader recognises — the case its column discovery exists to survive
// (wg-easy renamed it) and the one that used to be read as "wg-easy was never
// here".
func wgEasyDBWithoutAKey(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE interfaces_table (name TEXT PRIMARY KEY, port INTEGER, ipv4_cidr TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO interfaces_table VALUES ('wg0', 443, '10.8.0.1/24')`); err != nil {
		t.Fatal(err)
	}
}

// A database that is HERE but yields no key must never be read as "wg-easy was
// never set up on this host".
//
// Minting there rotates the master's client-facing identity, and because an
// existing key file wins on every later pass, nothing re-adopts. Everything looks
// fine until the handover, when every config in the field stops handshaking at
// once. Deferring costs a pass and is retried; minting is permanent.
func TestAdoptDefersWhenWGEasysDatabaseYieldsNoKey(t *testing.T) {
	a := quietAgent(t)
	wgEasyDBWithoutAKey(t, a.masterPaths().WGEasyDB)

	if _, state := a.adoptWGEasyKey(); state != adoptUnreadable {
		t.Fatalf("adoptWGEasyKey() state = %v, want adoptUnreadable", state)
	}

	// And the caller must hand back nothing rather than mint.
	kp, ephemeral, err := a.ensureClientWGKey(true)
	if err != nil {
		t.Fatalf("ensureClientWGKey() error = %v", err)
	}
	if kp.PrivateKey != "" || ephemeral {
		t.Errorf("a fresh key was minted anyway: %+v (ephemeral=%v)", kp.PublicKey, ephemeral)
	}
	if _, err := os.Stat(a.masterPaths().ClientWGKey); err == nil {
		t.Error("a key file was written, so no later pass can ever adopt wg-easy's key")
	}
}

// The other side of the same line: no database file at all means wg-easy really
// was never here, and minting is the right answer.
func TestAdoptMintsWhenWGEasyWasNeverInstalled(t *testing.T) {
	a := quietAgent(t)
	if _, err := os.Stat(a.masterPaths().WGEasyDB); err == nil {
		t.Fatal("fixture is wrong: the database exists")
	}
	if _, state := a.adoptWGEasyKey(); state != adoptAbsent {
		t.Fatalf("adoptWGEasyKey() state = %v, want adoptAbsent", state)
	}
	kp, _, err := a.ensureClientWGKey(true)
	if err != nil {
		t.Fatalf("ensureClientWGKey() error = %v", err)
	}
	if kp.PrivateKey == "" {
		t.Fatal("a master that never ran wg-easy must get a fresh key")
	}
}
