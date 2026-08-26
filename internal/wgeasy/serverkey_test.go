package wgeasy

import (
	"context"
	"database/sql"
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

func TestReadInterfacePrivateKeyMisses(t *testing.T) {
	ctx := context.Background()
	tests := map[string]string{
		"no such column":    newKeyDB(t, "", ""),
		"empty value":       newKeyDB(t, "private_key", ""),
		"database is empty": filepath.Join(t.TempDir(), "absent.db"),
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
