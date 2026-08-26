// Package wgeasy configures the client-facing wg-easy interface by writing
// directly to its SQLite database (/etc/wireguard/wg-easy.db). wg-easy has no
// env/API hook for AmneziaWG obfuscation — those params live as columns on its
// interfaces_table and are otherwise only settable through the Web UI. The
// transport columns (port, ipv4_cidr, mtu) ARE seedable via INIT_* env, but only
// on first DB creation: wg-easy ignores INIT_* once the DB exists, so a manifest
// change to the client port/pool/MTU would never take effect on a running node.
// To keep the interface truly declarative we reconcile both sets here: the
// AmneziaWG params (S1-S4, H1-H4, Jc/Jmin/Jmax) AND the transport columns
// (port, ipv4_cidr, mtu). wg-easy regenerates its wg0.conf and every client
// config from these columns on restart, so server and clients stay consistent.
//
// We also set the per-end I1-I5 signature packets: wg-easy does NOT seed those at
// first start (its docs say "all parameters except I1-I5 will be set at first
// startup"), so without writing them the client-facing interface would run with
// NO I-packet obfuscation while the exit interface has it — an inconsistent
// fingerprint. The derived I1-I5 are userspace-safe (no <c>/<t>); they are not
// copied to client configs by wg-easy (I1-I5 are per-end), so they only govern
// the server's emitted junk.
//
// We deliberately do NOT touch the private/public key (wg-easy owns its identity).
package wgeasy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "modernc.org/sqlite" // pure-Go sqlite driver

	"github.com/shidoh/wgfleet/internal/domain"
)

// DefaultDBPath is wg-easy's SQLite database location inside its container/host
// volume.
const DefaultDBPath = "/etc/wireguard/wg-easy.db"

// DefaultInterface is wg-easy's default interface name (and interfaces_table
// primary key).
const DefaultInterface = "wg0"

// InterfaceColumns is the subset of interfaces_table columns this package
// manages: the AmneziaWG obfuscation params plus the transport settings (port,
// ipv4_cidr, mtu) that must track the desired WGServerSpec. H values are
// AmneziaWG ranges rendered as "min-max" strings (the column type is text).
type InterfaceColumns struct {
	Port               int
	IPv4CIDR           string
	MTU                int
	Jc, Jmin, Jmax     int
	S1, S2, S3, S4     int
	H1, H2, H3, H4     string
	I1, I2, I3, I4, I5 string
}

// ColumnsFromParams maps domain AWG params onto the managed AWG columns only,
// leaving the transport fields (port/cidr/mtu) zero. Prefer ColumnsFromSpec when
// reconciling a real interface so the transport columns are enforced too.
func ColumnsFromParams(p domain.AWGParams) InterfaceColumns {
	return InterfaceColumns{
		Jc: p.Local.Jc, Jmin: p.Local.Jmin, Jmax: p.Local.Jmax,
		S1: p.Shared.S1, S2: p.Shared.S2, S3: p.Shared.S3, S4: p.Shared.S4,
		H1: p.Shared.H1.String(), H2: p.Shared.H2.String(),
		H3: p.Shared.H3.String(), H4: p.Shared.H4.String(),
		I1: p.Local.I1, I2: p.Local.I2, I3: p.Local.I3, I4: p.Local.I4, I5: p.Local.I5,
	}
}

// ColumnsFromSpec builds the full managed column set from the master's
// client-facing WGServerSpec: the AWG params plus the transport columns (listen
// port, address pool, MTU). The spec's AWG must be non-nil.
func ColumnsFromSpec(w domain.WGServerSpec) InterfaceColumns {
	c := ColumnsFromParams(*w.AWG)
	c.Port = w.ListenPort
	c.IPv4CIDR = w.AddressPool
	c.MTU = w.MTU
	return c
}

// RenderUpdateSQL returns a human-readable rendering of the UPDATE that
// UpdateInterface would run, for dry-run plan output. None of these columns are
// secret (public obfuscation params + transport settings).
func RenderUpdateSQL(name string, c InterfaceColumns) string {
	return fmt.Sprintf(
		"UPDATE interfaces_table SET\n"+
			"  port=%d, ipv4_cidr='%s', mtu=%d,\n"+
			"  j_c=%d, j_min=%d, j_max=%d,\n"+
			"  s1=%d, s2=%d, s3=%d, s4=%d,\n"+
			"  h1='%s', h2='%s', h3='%s', h4='%s',\n"+
			"  i1='%s', i2='%s', i3='%s', i4='%s', i5='%s'\n"+
			"WHERE name='%s';",
		c.Port, c.IPv4CIDR, c.MTU,
		c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4,
		c.H1, c.H2, c.H3, c.H4,
		c.I1, c.I2, c.I3, c.I4, c.I5, name)
}

// ReadInterface returns the interface's current managed columns. found is false
// (with no error) when the interface row does not exist yet; callers treat that
// as "wg-easy not set up yet" rather than a failure.
func ReadInterface(ctx context.Context, dbPath, name string) (cols InterfaceColumns, found bool, err error) {
	db, err := open(dbPath)
	if err != nil {
		return InterfaceColumns{}, false, err
	}
	defer func() { _ = db.Close() }()

	const q = `SELECT
		COALESCE(port,0), COALESCE(ipv4_cidr,''), COALESCE(mtu,0),
		COALESCE(j_c,0), COALESCE(j_min,0), COALESCE(j_max,0),
		COALESCE(s1,0), COALESCE(s2,0), COALESCE(s3,0), COALESCE(s4,0),
		COALESCE(h1,''), COALESCE(h2,''), COALESCE(h3,''), COALESCE(h4,''),
		COALESCE(i1,''), COALESCE(i2,''), COALESCE(i3,''), COALESCE(i4,''), COALESCE(i5,'')
		FROM interfaces_table WHERE name = ?`
	row := db.QueryRowContext(ctx, q, name)
	err = row.Scan(
		&cols.Port, &cols.IPv4CIDR, &cols.MTU,
		&cols.Jc, &cols.Jmin, &cols.Jmax,
		&cols.S1, &cols.S2, &cols.S3, &cols.S4,
		&cols.H1, &cols.H2, &cols.H3, &cols.H4,
		&cols.I1, &cols.I2, &cols.I3, &cols.I4, &cols.I5,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return InterfaceColumns{}, false, nil
	}
	if err != nil {
		return InterfaceColumns{}, false, fmt.Errorf("read wg-easy interface %q: %w", name, err)
	}
	return cols, true, nil
}

// UpdateInterface applies the managed columns to the interface row. It errors if
// the interface does not exist (wg-easy must be set up first).
func UpdateInterface(ctx context.Context, dbPath, name string, c InterfaceColumns) error {
	db, err := open(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	const q = `UPDATE interfaces_table SET
		port=?, ipv4_cidr=?, mtu=?,
		j_c=?, j_min=?, j_max=?,
		s1=?, s2=?, s3=?, s4=?,
		h1=?, h2=?, h3=?, h4=?,
		i1=?, i2=?, i3=?, i4=?, i5=?
		WHERE name=?`
	res, err := db.ExecContext(ctx, q,
		c.Port, c.IPv4CIDR, c.MTU,
		c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4,
		c.H1, c.H2, c.H3, c.H4,
		c.I1, c.I2, c.I3, c.I4, c.I5, name)
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

// openReadOnly opens wg-easy's database for READING without creating it.
//
// The default DSN below opens with CREATE, which is right for the writeback
// paths and catastrophic for the read ones: a file conjured by a read looks to
// every wg-easy planner like a set-up-but-empty install, so they query it, hit
// "no such table", and abort the master's whole reconcile pass — permanently,
// since the file does not go away. It also makes server-key adoption a one-shot
// that silently missed, which cuts off every client at cutover.
//
// A missing file is reported as os.ErrNotExist so callers can tell "wg-easy was
// never here" (nothing to read) from "wg-easy is here but unreadable" (defer and
// try again) — two answers that must never be collapsed.
func openReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(5000)", path))
	if err != nil {
		return nil, fmt.Errorf("open wg-easy db %q read-only: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
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
