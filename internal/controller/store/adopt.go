package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// MarkerDevicesFromWG records that the one-shot adoption has run.
const MarkerDevicesFromWG = "devices-from-wg-credentials"

// MarkerAWGRotationByMaster records that the pinned-port generations have been
// carried over to the base master.
const MarkerAWGRotationByMaster = "awg-rotation-by-master"

// AdoptedDeviceID is the ID an adopted credential's device gets. DERIVED, not
// random: the adoption must be a pure function of the store's state, so every
// replica that replays it (ADR-0027, phase B) arrives at the same rows.
func AdoptedDeviceID(masterID, credID string) string {
	sum := sha256.Sum256([]byte("wgfleet|device-adopt|v1|" + masterID + "|" + credID))
	return hex.EncodeToString(sum[:16])
}

// AdoptWGCredentialsAsDevices implements Store.
//
// Every AWG credential without a device becomes a device of its own, named after
// it, whose TOKEN IS THE CREDENTIAL ID — every portal link already handed out
// (/c/{id} and the reserve /c/{id}/l/{exit}/…) keeps working, now through the
// device. The credential's own link is retired in the same statement, so deleting
// the device later cannot bring the ID back as a second, forgotten door. VLESS
// credentials are left alone: which AWG credential a VLESS one belongs with is
// the operator's knowledge, not the store's.
//
// One transaction, and marked: a second run would wrap credentials the operator
// has since left without a device on purpose. Under raft only the leader will
// issue it (phase B).
func (s *SQLiteStore) AdoptWGCredentialsAsDevices(ctx context.Context, at time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("adopt devices: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var marker string
	switch err := tx.QueryRowContext(ctx, `SELECT name FROM store_markers WHERE name=?`, MarkerDevicesFromWG).Scan(&marker); {
	case err == nil:
		return 0, nil
	case !errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("adopt devices: read marker: %w", err)
	}

	type cred struct{ master, id, name, createdAt string }
	// master_id, created_at, id: the order decides who keeps a bare name in a
	// collision, and must be the same on every replica.
	rows, err := tx.QueryContext(ctx, `SELECT master_id, id, name, created_at FROM client_wg_credentials
		WHERE device_id IS NULL ORDER BY master_id, created_at, id`)
	if err != nil {
		return 0, fmt.Errorf("adopt devices: list credentials: %w", err)
	}
	var creds []cred
	for rows.Next() {
		var c cred
		if err := rows.Scan(&c.master, &c.id, &c.name, &c.createdAt); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("adopt devices: scan: %w", err)
		}
		creds = append(creds, c)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("adopt devices: list credentials: %w", err)
	}

	taken, err := deviceNames(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, c := range creds {
		name := uniqueDeviceName(c.name, c.master, taken)
		taken[name] = true
		id := AdoptedDeviceID(c.master, c.id)
		createdAt := c.createdAt
		if createdAt == "" {
			createdAt = fmtTime(at.UTC())
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO client_devices (id, token, name, created_at) VALUES (?,?,?,?)`,
			id, c.id, name, createdAt); err != nil {
			return 0, fmt.Errorf("adopt devices: create %q: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE client_wg_credentials SET device_id=?, legacy_link_retired=1 WHERE master_id=? AND id=?`,
			id, c.master, c.id); err != nil {
			return 0, fmt.Errorf("adopt devices: attach %q: %w", c.id, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO store_markers (name, applied_at) VALUES (?,?)`,
		MarkerDevicesFromWG, fmtTime(at.UTC())); err != nil {
		return 0, fmt.Errorf("adopt devices: mark: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("adopt devices: commit: %w", err)
	}
	return len(creds), nil
}

func deviceNames(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM client_devices`)
	if err != nil {
		return nil, fmt.Errorf("adopt devices: list names: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("adopt devices: scan name: %w", err)
		}
		out[n] = true
	}
	return out, rows.Err()
}

// uniqueDeviceName keeps the credential's own label when free, then tries
// "<name>-<master>", then numbered variants. The NAME is trimmed, never the
// suffix, so the result stays within domain.MaxClientNameLen and still says
// which master it came from.
func uniqueDeviceName(name, master string, taken map[string]bool) string {
	if !taken[name] {
		return name
	}
	for i := 1; ; i++ {
		suffix := "-" + master
		if i > 1 {
			suffix = fmt.Sprintf("-%s-%d", master, i)
		}
		if len(suffix) >= domain.MaxClientNameLen {
			suffix = suffix[len(suffix)-(domain.MaxClientNameLen-1):]
		}
		base := name
		if room := domain.MaxClientNameLen - len(suffix); len(base) > room {
			base = base[:room]
		}
		if cand := base + suffix; !taken[cand] {
			return cand
		}
	}
}

// AdoptAWGPortRotation implements Store.
//
// The generations of the single-master days belong to the one master there was;
// starting them over at 0 would hand an exit back the port a path filter already
// poisoned. One transaction, and marked: a second run with another master would
// hand it a history its tunnels never had.
func (s *SQLiteStore) AdoptAWGPortRotation(ctx context.Context, master string) (int, error) {
	if master == "" {
		return 0, errors.New("store: master name is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("adopt awg rotation: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var marker string
	switch err := tx.QueryRowContext(ctx, `SELECT name FROM store_markers WHERE name=?`, MarkerAWGRotationByMaster).Scan(&marker); {
	case err == nil:
		return 0, nil
	case !errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("adopt awg rotation: read marker: %w", err)
	}
	// OR IGNORE: a tunnel that already has a row of its own is newer than the copy.
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO awg_pin_rotation (master_id, exit_id, generation, rotated_at)
		 SELECT ?, node_id, generation, rotated_at FROM awg_port_rotation`, master)
	if err != nil {
		return 0, fmt.Errorf("adopt awg rotation for %q: %w", master, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO store_markers (name, applied_at) VALUES (?,?)`,
		MarkerAWGRotationByMaster, fmtTime(s.now().UTC())); err != nil {
		return 0, fmt.Errorf("adopt awg rotation: mark: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("adopt awg rotation: commit: %w", err)
	}
	return int(n), nil
}
