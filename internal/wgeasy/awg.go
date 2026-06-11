// Package wgeasy configures the AmneziaWG obfuscation of a wg-easy instance by
// writing directly to its SQLite database (/etc/wireguard/wg-easy.db). wg-easy
// has no env/API hook for obfuscation params — they live as columns on its
// interfaces_table and are otherwise only settable through the Web UI. We set
// the shared params (S1-S4, H1-H4) plus the junk params (Jc/Jmin/Jmax) on the
// interface; wg-easy propagates S/H to every client config automatically (its
// client generator inherits the interface's S/H, exactly matching the AmneziaWG
// rule), so a single interface update keeps server and clients consistent.
//
// We deliberately do NOT touch the private/public key (wg-easy owns its identity)
// nor I1-I5 (per-end, UI/operator-managed).
package wgeasy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go sqlite driver

	"github.com/shidoh/wgfleet/internal/domain"
)

// DefaultDBPath is wg-easy's SQLite database location inside its container/host
// volume.
const DefaultDBPath = "/etc/wireguard/wg-easy.db"

// DefaultInterface is wg-easy's default interface name (and interfaces_table
// primary key).
const DefaultInterface = "wg0"

// AWGColumns is the subset of interfaces_table columns this package manages. H
// values are AmneziaWG ranges rendered as "min-max" strings (the column type is
// text in wg-easy).
type AWGColumns struct {
	Jc, Jmin, Jmax int
	S1, S2, S3, S4 int
	H1, H2, H3, H4 string
}

// ColumnsFromParams maps domain AWG params onto the managed columns.
func ColumnsFromParams(p domain.AWGParams) AWGColumns {
	return AWGColumns{
		Jc: p.Local.Jc, Jmin: p.Local.Jmin, Jmax: p.Local.Jmax,
		S1: p.Shared.S1, S2: p.Shared.S2, S3: p.Shared.S3, S4: p.Shared.S4,
		H1: p.Shared.H1.String(), H2: p.Shared.H2.String(),
		H3: p.Shared.H3.String(), H4: p.Shared.H4.String(),
	}
}

// RenderUpdateSQL returns a human-readable rendering of the UPDATE that
// UpdateAWG would run, for dry-run plan output. AWG params are not secret.
func RenderUpdateSQL(name string, c AWGColumns) string {
	return fmt.Sprintf(
		"UPDATE interfaces_table SET\n"+
			"  j_c=%d, j_min=%d, j_max=%d,\n"+
			"  s1=%d, s2=%d, s3=%d, s4=%d,\n"+
			"  h1='%s', h2='%s', h3='%s', h4='%s'\n"+
			"WHERE name='%s';",
		c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4,
		c.H1, c.H2, c.H3, c.H4, name)
}

// ReadAWG returns the interface's current managed AWG columns. found is false
// (with no error) when the interface row does not exist yet; callers treat that
// as "wg-easy not set up yet" rather than a failure.
func ReadAWG(ctx context.Context, dbPath, name string) (cols AWGColumns, found bool, err error) {
	db, err := open(dbPath)
	if err != nil {
		return AWGColumns{}, false, err
	}
	defer func() { _ = db.Close() }()

	const q = `SELECT
		COALESCE(j_c,0), COALESCE(j_min,0), COALESCE(j_max,0),
		COALESCE(s1,0), COALESCE(s2,0), COALESCE(s3,0), COALESCE(s4,0),
		COALESCE(h1,''), COALESCE(h2,''), COALESCE(h3,''), COALESCE(h4,'')
		FROM interfaces_table WHERE name = ?`
	row := db.QueryRowContext(ctx, q, name)
	err = row.Scan(
		&cols.Jc, &cols.Jmin, &cols.Jmax,
		&cols.S1, &cols.S2, &cols.S3, &cols.S4,
		&cols.H1, &cols.H2, &cols.H3, &cols.H4,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AWGColumns{}, false, nil
	}
	if err != nil {
		return AWGColumns{}, false, fmt.Errorf("read wg-easy interface %q: %w", name, err)
	}
	return cols, true, nil
}

// UpdateAWG applies the managed AWG columns to the interface row. It errors if
// the interface does not exist (wg-easy must be set up first).
func UpdateAWG(ctx context.Context, dbPath, name string, c AWGColumns) error {
	db, err := open(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	const q = `UPDATE interfaces_table SET
		j_c=?, j_min=?, j_max=?,
		s1=?, s2=?, s3=?, s4=?,
		h1=?, h2=?, h3=?, h4=?
		WHERE name=?`
	res, err := db.ExecContext(ctx, q,
		c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4,
		c.H1, c.H2, c.H3, c.H4, name)
	if err != nil {
		return fmt.Errorf("update wg-easy interface %q: %w", name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update wg-easy interface %q: %w", name, err)
	}
	if n == 0 {
		return fmt.Errorf("wg-easy interface %q not found (set up wg-easy first)", name)
	}
	return nil
}

func open(path string) (*sql.DB, error) {
	// busy_timeout guards against wg-easy holding the DB during a sync.
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)", path))
	if err != nil {
		return nil, fmt.Errorf("open wg-easy db %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
