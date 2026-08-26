package wgeasy

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Reading wg-easy's issued clients, for the one-shot import that moves the
// client leg into the controller's own store.
//
// Everything here is schema-tolerant on purpose. We do not own this schema, it
// has moved under us before, and this code runs exactly once per node — so the
// cost of discovering column names is paid once, while the cost of guessing them
// wrong is an import that silently drops half the fleet's clients.

// ImportedClient is one credential as wg-easy holds it.
type ImportedClient struct {
	Name         string
	Address      string // with mask when wg-easy stored one; the importer normalizes
	PublicKey    string
	PrivateKey   string
	PresharedKey string
	Enabled      bool
	CreatedAt    time.Time
}

// clientColumns maps our field names onto whatever this database calls them.
type clientColumns struct {
	table                               string
	name, address                       string
	publicKey, privateKey, presharedKey string
	enabled, disabled, createdAt        string
}

// ReadClients returns every credential wg-easy has issued, ordered by name.
// found is false (no error) when the database has no recognizable clients table
// — an empty or never-set-up wg-easy, which is a legitimate "nothing to import".
func ReadClients(ctx context.Context, dbPath string) (clients []ImportedClient, found bool, err error) {
	db, err := open(dbPath)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = db.Close() }()

	cols, ok, err := discoverClientColumns(ctx, db)
	if err != nil || !ok {
		return nil, false, err
	}

	selected := []string{cols.name, cols.address, cols.publicKey, cols.privateKey}
	optional := []string{cols.presharedKey, cols.enabled, cols.disabled, cols.createdAt}
	for _, c := range optional {
		if c != "" {
			selected = append(selected, c)
		}
	}
	// #nosec G202 -- every name comes from PRAGMA table_info and was matched
	// against safeColumn in discoverClientColumns.
	q := fmt.Sprintf("SELECT %s FROM %s", strings.Join(selected, ", "), cols.table)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, false, fmt.Errorf("read wg-easy clients: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			name, address, pub, priv sql.NullString
			psk, created             sql.NullString
			enabled, disabled        sql.NullInt64
		)
		dest := []any{&name, &address, &pub, &priv}
		for _, c := range optional {
			switch c {
			case "":
			case cols.presharedKey:
				dest = append(dest, &psk)
			case cols.enabled:
				dest = append(dest, &enabled)
			case cols.disabled:
				dest = append(dest, &disabled)
			case cols.createdAt:
				dest = append(dest, &created)
			}
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, false, fmt.Errorf("scan wg-easy client: %w", err)
		}
		clients = append(clients, ImportedClient{
			Name:         strings.TrimSpace(name.String),
			Address:      strings.TrimSpace(address.String),
			PublicKey:    strings.TrimSpace(pub.String),
			PrivateKey:   strings.TrimSpace(priv.String),
			PresharedKey: strings.TrimSpace(psk.String),
			Enabled:      resolveEnabled(cols, enabled, disabled),
			CreatedAt:    parseSQLiteTime(created.String),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("read wg-easy clients: %w", err)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Name < clients[j].Name })
	return clients, true, nil
}

// resolveEnabled reads whichever of the two spellings this schema uses. With
// neither, a credential counts as enabled: wg-easy without a disable column
// cannot have disabled anyone.
func resolveEnabled(cols clientColumns, enabled, disabled sql.NullInt64) bool {
	switch {
	case cols.enabled != "" && enabled.Valid:
		return enabled.Int64 != 0
	case cols.disabled != "" && disabled.Valid:
		return disabled.Int64 == 0
	default:
		return true
	}
}

// discoverClientColumns finds the clients table and maps its columns. ok is false
// when no table carries the minimum set (a name, an address and both keys),
// which is what an un-set-up wg-easy looks like.
func discoverClientColumns(ctx context.Context, db *sql.DB) (clientColumns, bool, error) {
	tables, err := listTables(ctx, db)
	if err != nil {
		return clientColumns{}, false, err
	}
	// clients_table is wg-easy's own name; try it first, then anything else that
	// mentions clients, so a rename does not defeat the import.
	sort.Slice(tables, func(i, j int) bool {
		return tables[i] == "clients_table" && tables[j] != "clients_table"
	})

	for _, table := range tables {
		if !strings.Contains(table, "client") {
			continue
		}
		names, err := columnNames(ctx, db, table)
		if err != nil {
			return clientColumns{}, false, err
		}
		cols := clientColumns{
			table:        table,
			name:         pickColumn(names, "name"),
			address:      pickColumn(names, "ipv4_address", "address", "ipv4", "ip"),
			publicKey:    pickColumn(names, "public_key", "publickey"),
			privateKey:   pickColumn(names, "private_key", "privatekey"),
			presharedKey: pickColumn(names, "preshared_key", "pre_shared_key", "presharedkey"),
			enabled:      pickColumn(names, "enabled"),
			disabled:     pickColumn(names, "disabled"),
			createdAt:    pickColumn(names, "created_at", "createdat"),
		}
		if cols.name != "" && cols.address != "" && cols.publicKey != "" && cols.privateKey != "" {
			return cols, true, nil
		}
	}
	return clientColumns{}, false, nil
}

// pickColumn returns the first candidate present among names, preferring exact
// matches in the order given.
func pickColumn(names []string, candidates ...string) string {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	for _, c := range candidates {
		if _, ok := set[c]; ok {
			return c
		}
	}
	return ""
}

func listTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return nil, fmt.Errorf("list wg-easy tables: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan wg-easy table name: %w", err)
		}
		name = strings.ToLower(name)
		if safeColumn.MatchString(name) {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}

func columnNames(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	// #nosec G201 -- table came from sqlite_master and passed safeColumn.
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", table, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var (
			cid        int
			name       string
			ctype      sql.NullString
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &defaultVal, &pk); err != nil {
			return nil, fmt.Errorf("scan %s schema: %w", table, err)
		}
		name = strings.ToLower(name)
		if safeColumn.MatchString(name) {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}

// parseSQLiteTime accepts the shapes wg-easy has used for timestamps. An
// unparseable or absent value yields the zero time, and the importer stamps the
// import moment instead.
func parseSQLiteTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
