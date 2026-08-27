package wgeasy

import (
	"context"
	"path/filepath"
	"testing"
)

// newClientsDB builds a throwaway wg-easy-shaped database. ddl and inserts are
// given verbatim so each test can describe a different schema generation.
func newClientsDB(t *testing.T, statements ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg-easy.db")
	db, err := open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
	return path
}

func TestReadClients(t *testing.T) {
	path := newClientsDB(t,
		`CREATE TABLE clients_table (
			id TEXT, name TEXT, ipv4_address TEXT, public_key TEXT, private_key TEXT,
			preshared_key TEXT, enabled INTEGER, created_at TEXT)`,
		`INSERT INTO clients_table VALUES
			('2','phone','10.8.0.3','pub-phone','priv-phone','psk-phone',0,'2026-08-01 10:00:00'),
			('1','laptop','10.8.0.2','pub-laptop','priv-laptop','',1,'2026-07-01T09:30:00Z')`,
	)

	got, found, err := ReadClients(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadClients() error = %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if len(got) != 2 {
		t.Fatalf("read %d clients, want 2: %+v", len(got), got)
	}
	// Ordered by name so a dry-run prints the same list twice in a row.
	if got[0].Name != "laptop" || got[1].Name != "phone" {
		t.Fatalf("order = %q, %q; want laptop, phone", got[0].Name, got[1].Name)
	}
	laptop := got[0]
	if laptop.Address != "10.8.0.2" || laptop.PublicKey != "pub-laptop" || laptop.PrivateKey != "priv-laptop" {
		t.Errorf("laptop = %+v", laptop)
	}
	if !laptop.Enabled {
		t.Error("laptop came back disabled")
	}
	if laptop.CreatedAt.IsZero() {
		t.Error("laptop lost its creation timestamp")
	}
	if got[1].Enabled {
		t.Error("phone was disabled in wg-easy and must import muted")
	}
	if got[1].PresharedKey != "psk-phone" {
		t.Errorf("phone preshared key = %q", got[1].PresharedKey)
	}
}

// A schema that spells the disable flag the other way round must still import
// with the right state — the difference decides whether a revoked client comes
// back to life.
func TestReadClientsHonoursDisabledColumn(t *testing.T) {
	path := newClientsDB(t,
		`CREATE TABLE clients_table (name TEXT, address TEXT, publickey TEXT, privatekey TEXT, disabled INTEGER)`,
		`INSERT INTO clients_table VALUES ('laptop','10.8.0.2/32','pub','priv',1)`,
	)
	got, found, err := ReadClients(context.Background(), path)
	if err != nil || !found {
		t.Fatalf("ReadClients() = %v, found %v", err, found)
	}
	if got[0].Enabled {
		t.Fatal("a client marked disabled imported as enabled")
	}
	if got[0].Address != "10.8.0.2/32" {
		t.Fatalf("address = %q", got[0].Address)
	}
}

// Neither flag column present: everyone is enabled, because a wg-easy that
// cannot disable anyone has not disabled anyone.
func TestReadClientsWithoutAnEnabledColumn(t *testing.T) {
	path := newClientsDB(t,
		`CREATE TABLE clients_table (name TEXT, ipv4_address TEXT, public_key TEXT, private_key TEXT)`,
		`INSERT INTO clients_table VALUES ('laptop','10.8.0.2','pub','priv')`,
	)
	got, _, err := ReadClients(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadClients() error = %v", err)
	}
	if !got[0].Enabled {
		t.Fatal("client imported muted from a schema with no disable flag")
	}
}

func TestReadClientsNothingToImport(t *testing.T) {
	tests := map[string]string{
		"no clients table": newClientsDB(t, `CREATE TABLE general_table (id INTEGER)`),
		"unusable columns": newClientsDB(t, `CREATE TABLE clients_table (id TEXT, note TEXT)`),
		"absent database":  filepath.Join(t.TempDir(), "missing.db"),
	}
	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			got, found, err := ReadClients(context.Background(), path)
			if err != nil {
				t.Fatalf("ReadClients() error = %v", err)
			}
			if found || len(got) != 0 {
				t.Fatalf("found = %v with %d clients; want nothing to import", found, len(got))
			}
		})
	}
}
