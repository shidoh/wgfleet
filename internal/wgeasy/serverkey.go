package wgeasy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ReadInterfacePrivateKey returns the private key wg-easy generated for its
// client-facing interface. found is false (no error) when the database, the row,
// or the column is absent.
//
// This is the hinge of the transparent migration. When the agent takes the client
// leg over it ADOPTS this key instead of minting a new one, so the server public
// key every already-configured client pins keeps matching and nobody has to
// re-import a tunnel. It is read exactly ONCE per node — afterwards the key lives
// in the agent's own key file and wg-easy's schema stops mattering, which is the
// opposite of the permanent writeback relationship we are leaving behind.
//
// The column is discovered rather than assumed. We do not control that schema and
// it has moved under us before (their migrations renamed and added columns while
// we wrote to them), so a hard-coded name would turn a rename into "the agent
// silently minted a new server key and cut every client off". Discovery turns the
// same event into found=false, which the caller treats as "nothing to adopt".
func ReadInterfacePrivateKey(ctx context.Context, dbPath, name string) (key string, found bool, err error) {
	db, err := open(dbPath)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = db.Close() }()

	column, err := privateKeyColumn(ctx, db)
	if err != nil || column == "" {
		return "", false, err
	}

	var v sql.NullString
	// #nosec G201 -- column comes from PRAGMA table_info and is matched against
	// safeColumn below, so it cannot carry anything but [a-z0-9_].
	q := fmt.Sprintf(`SELECT %s FROM interfaces_table WHERE name = ?`, column)
	err = db.QueryRowContext(ctx, q, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read wg-easy interface key %q: %w", name, err)
	}
	if !v.Valid || strings.TrimSpace(v.String) == "" {
		return "", false, nil
	}
	return strings.TrimSpace(v.String), true, nil
}

// safeColumn bounds what we are willing to interpolate into a query, even though
// the value comes from the database's own schema.
var safeColumn = regexp.MustCompile(`^[a-z0-9_]+$`)

// privateKeyColumn finds the interface private-key column in whatever schema
// version this wg-easy happens to be on. It returns "" (no error) when the table
// or a plausible column is missing.
func privateKeyColumn(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(interfaces_table)`)
	if err != nil {
		return "", fmt.Errorf("inspect wg-easy interfaces_table: %w", err)
	}
	defer rows.Close()

	var candidate string
	for rows.Next() {
		var (
			cid        int
			nameCol    string
			ctype      sql.NullString
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &nameCol, &ctype, &notNull, &defaultVal, &pk); err != nil {
			return "", fmt.Errorf("scan wg-easy interfaces_table schema: %w", err)
		}
		nameCol = strings.ToLower(nameCol)
		if !safeColumn.MatchString(nameCol) {
			continue
		}
		switch {
		case nameCol == "private_key":
			return nameCol, nil // exact match wins outright
		case strings.Contains(nameCol, "private") && strings.Contains(nameCol, "key"):
			candidate = nameCol
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("inspect wg-easy interfaces_table: %w", err)
	}
	return candidate, nil
}
