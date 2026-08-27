package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Client-facing WireGuard credentials (the leg that used to belong to wg-easy).
// They live in their own file rather than in sqlite.go because they are the only
// rows in this store that hold an end-user secret, and that deserves to be read
// in one place.

// ListWGClients implements Store.
func (s *SQLiteStore) ListWGClients(ctx context.Context, masterID string) ([]domain.WGClient, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, address, public_key, private_key, preshared_key, enabled, created_at
		 FROM client_wg_credentials WHERE master_id=? ORDER BY name`, masterID)
	if err != nil {
		return nil, fmt.Errorf("list wg clients for %q: %w", masterID, err)
	}
	defer rows.Close()

	var out []domain.WGClient
	for rows.Next() {
		var (
			c         domain.WGClient
			enabled   int
			createdAt string
		)
		if err := rows.Scan(&c.ID, &c.Name, &c.Address, &c.PublicKey, &c.PrivateKey,
			&c.PresharedKey, &enabled, &createdAt); err != nil {
			return nil, fmt.Errorf("scan wg client for %q: %w", masterID, err)
		}
		c.Enabled = enabled != 0
		c.CreatedAt = parseTime(createdAt)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list wg clients for %q: %w", masterID, err)
	}
	return out, nil
}

// AddWGClient implements Store.
func (s *SQLiteStore) AddWGClient(ctx context.Context, masterID string, c domain.WGClient) error {
	switch {
	case masterID == "":
		return errors.New("store: master ID is required")
	case c.ID == "":
		return errors.New("store: client ID is required")
	case c.Name == "":
		return errors.New("store: client name is required")
	case c.Address == "":
		return errors.New("store: client address is required")
	case c.PublicKey == "":
		return errors.New("store: client public key is required")
	case c.CreatedAt.IsZero():
		// Refused rather than defaulted to now(). A clock read inside the write is
		// exactly what the mint-then-store split exists to remove: under a replicated
		// control plane (ADR-0027) every replica applying this record would stamp a
		// different time. The caller decides when the credential was issued.
		return errors.New("store: client CreatedAt is required (the caller stamps it, not the store)")
	}
	// The master row must exist: the FK would reject the insert anyway, but only as
	// an opaque constraint error. Check first so the caller gets ErrNotFound and the
	// web layer can report "master not registered" (mirrors AddVLESSClient).
	if _, err := s.GetNode(ctx, masterID); err != nil {
		return err
	}
	// A plain INSERT, not an upsert: re-issuing a name must NOT silently replace a
	// live credential's keys — that would cut the existing client off with no trace.
	// The UNIQUE constraints turn both collisions into an error the UI reports.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO client_wg_credentials
			(master_id, id, name, address, public_key, private_key, preshared_key, enabled, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		masterID, c.ID, c.Name, c.Address, c.PublicKey, c.PrivateKey, c.PresharedKey,
		boolToInt(c.Enabled), fmtTime(c.CreatedAt.UTC()))
	if err != nil {
		return fmt.Errorf("add wg client %q for %q: %w", c.Name, masterID, err)
	}
	return nil
}

// SetWGClientEnabled implements Store.
func (s *SQLiteStore) SetWGClientEnabled(ctx context.Context, masterID, clientID string, enabled bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE client_wg_credentials SET enabled=? WHERE master_id=? AND id=?`,
		boolToInt(enabled), masterID, clientID)
	if err != nil {
		return fmt.Errorf("set enabled for wg client %q of %q: %w", clientID, masterID, err)
	}
	return requireAffected(res)
}

// RenameWGClient implements Store.
func (s *SQLiteStore) RenameWGClient(ctx context.Context, masterID, clientID, name string) error {
	if name == "" {
		return errors.New("store: client name is required")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE client_wg_credentials SET name=? WHERE master_id=? AND id=?`,
		name, masterID, clientID)
	if err != nil {
		return fmt.Errorf("rename wg client %q of %q: %w", clientID, masterID, err)
	}
	return requireAffected(res)
}

// RemoveWGClient implements Store.
func (s *SQLiteStore) RemoveWGClient(ctx context.Context, masterID, clientID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM client_wg_credentials WHERE master_id=? AND id=?`, masterID, clientID)
	if err != nil {
		return fmt.Errorf("remove wg client %q of %q: %w", clientID, masterID, err)
	}
	return requireAffected(res)
}
