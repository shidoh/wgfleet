package wgeasy

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// newKeyDB creates a throwaway database with an interfaces_table shaped like
// wg-easy's, using the given private-key column name.
func newKeyDB(t *testing.T, keyColumn, keyValue string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg-easy.db")
	db, err := open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ddl := `CREATE TABLE interfaces_table (name TEXT PRIMARY KEY, port INTEGER, ipv4_cidr TEXT`
	if keyColumn != "" {
		ddl += `, ` + keyColumn + ` TEXT`
	}
	ddl += `)`
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if keyColumn != "" {
		if _, err := db.Exec(
			`INSERT INTO interfaces_table (name, port, ipv4_cidr, `+keyColumn+`) VALUES ('wg0', 443, '10.8.0.1/24', ?)`,
			sql.NullString{String: keyValue, Valid: keyValue != ""}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	} else if _, err := db.Exec(
		`INSERT INTO interfaces_table (name, port, ipv4_cidr) VALUES ('wg0', 443, '10.8.0.1/24')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return path
}

func TestReadInterfacePrivateKey(t *testing.T) {
	ctx := context.Background()
	path := newKeyDB(t, "private_key", "  c2VydmVyLWtleQ==  ")

	got, found, err := ReadInterfacePrivateKey(ctx, path, "wg0")
	if err != nil {
		t.Fatalf("ReadInterfacePrivateKey() error = %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if got != "c2VydmVyLWtleQ==" {
		t.Fatalf("key = %q, want the trimmed value", got)
	}
}

// The column name is discovered, not assumed: a renamed column in a later
// wg-easy schema must still be adopted rather than silently missed.
func TestReadInterfacePrivateKeyFindsRenamedColumn(t *testing.T) {
	path := newKeyDB(t, "wg_private_key", "c2VydmVyLWtleQ==")
	got, found, err := ReadInterfacePrivateKey(context.Background(), path, "wg0")
	if err != nil {
		t.Fatalf("ReadInterfacePrivateKey() error = %v", err)
	}
	if !found || got != "c2VydmVyLWtleQ==" {
		t.Fatalf("key = %q, found = %v; want the value from the renamed column", got, found)
	}
}

// Reading must never CREATE the database. wg-easy's absence is a legitimate
// state (a master that never ran it), and a file conjured by a read would then
// look to every wg-easy planner like a set-up-but-empty install — they would
// query it, hit "no such table", and abort the master's whole reconcile pass.
// It would also make key adoption a one-shot that silently missed.
func TestReadInterfacePrivateKeyDoesNotCreateTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	_, found, err := ReadInterfacePrivateKey(context.Background(), path, "wg0")
	if err != nil || found {
		t.Fatalf("ReadInterfacePrivateKey() on an absent database = found %v, err %v; want (false, nil)", found, err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatalf("reading an absent database created %s", path)
	}
}

func TestReadClientsDoesNotCreateTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	_, found, err := ReadClients(context.Background(), path)
	if err != nil || found {
		t.Fatalf("ReadClients() on an absent database = found %v, err %v; want (false, nil)", found, err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatalf("reading an absent database created %s", path)
	}
}

// A database that EXISTS but cannot be read is a different answer from one that
// is absent, and the caller must be able to tell them apart: the first means
// "defer, wg-easy may be mid-write", the second means "there is nothing to
// adopt". Collapsing them is how a master mints a fresh server key and cuts off
// every client that pins the old one.
func TestReadInterfacePrivateKeyReportsAnUnreadableDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, found, err := ReadInterfacePrivateKey(context.Background(), path, "wg0")
	if err == nil {
		t.Fatalf("ReadInterfacePrivateKey() on a corrupt database = found %v, nil error; want an error", found)
	}
}

func TestReadInterfacePrivateKeyMisses(t *testing.T) {
	ctx := context.Background()
	tests := map[string]string{
		"no such column": newKeyDB(t, "", ""),
		"empty value":    newKeyDB(t, "private_key", ""),
	}
	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			got, found, err := ReadInterfacePrivateKey(ctx, path, "wg0")
			if err != nil {
				t.Fatalf("ReadInterfacePrivateKey() error = %v", err)
			}
			if found || got != "" {
				t.Fatalf("key = %q, found = %v; want nothing to adopt", got, found)
			}
		})
	}
}

func TestReadInterfacePrivateKeyUnknownInterface(t *testing.T) {
	path := newKeyDB(t, "private_key", "c2VydmVyLWtleQ==")
	_, found, err := ReadInterfacePrivateKey(context.Background(), path, "wg9")
	if err != nil {
		t.Fatalf("ReadInterfacePrivateKey() error = %v", err)
	}
	if found {
		t.Fatal("found = true for an interface that is not in the table")
	}
}
