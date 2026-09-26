package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Client devices (ADR-0035). Every write here is ONE statement or ONE
// transaction, and every non-deterministic input — ID, token, time — arrives
// from the caller: under ADR-0027 the write is replayed on each replica and must
// land identically. The store runs on a single connection (SetMaxOpenConns(1)),
// so a token lookup and an attach/detach never interleave.

var (
	// ErrDeviceSlotTaken: the device already holds a credential of that kind on
	// that master.
	ErrDeviceSlotTaken = errors.New("store: the device already has a credential of this kind on this master")
	// ErrCredentialAttached: the credential belongs to another device. Moving it is
	// detach-then-attach, two acts the operator sees, never one silent one.
	ErrCredentialAttached = errors.New("store: the credential is attached to another device")
)

// credentialSQL is the closed set of per-kind statements; table and column
// names never come from input.
type credentialSQL struct {
	readDevice, attach, detach string
}

var credentialStmts = map[domain.CredentialKind]credentialSQL{
	domain.CredentialAWG: {
		readDevice: `SELECT device_id FROM client_wg_credentials WHERE master_id=? AND id=?`,
		// Attaching retires the personal link in the same statement.
		attach: `UPDATE client_wg_credentials SET device_id=?, legacy_link_retired=1 WHERE master_id=? AND id=?`,
		detach: `UPDATE client_wg_credentials SET device_id=NULL WHERE master_id=? AND id=?`,
	},
	domain.CredentialVLESS: {
		readDevice: `SELECT device_id FROM client_vless_credentials WHERE master_id=? AND name=?`,
		attach:     `UPDATE client_vless_credentials SET device_id=? WHERE master_id=? AND name=?`,
		detach:     `UPDATE client_vless_credentials SET device_id=NULL WHERE master_id=? AND name=?`,
	},
}

func stmtsFor(kind domain.CredentialKind) (credentialSQL, error) {
	q, ok := credentialStmts[kind]
	if !ok {
		return credentialSQL{}, fmt.Errorf("store: unknown credential kind %q", kind)
	}
	return q, nil
}

// CreateDevice implements Store.
func (s *SQLiteStore) CreateDevice(ctx context.Context, d domain.ClientDevice) error {
	switch {
	case d.ID == "", d.Token == "", d.Name == "":
		return errors.New("store: device ID, token and name are required")
	case d.CreatedAt.IsZero():
		return errors.New("store: device CreatedAt is required (the caller stamps it, not the store)")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO client_devices (id, token, name, created_at) VALUES (?,?,?,?)`,
		d.ID, d.Token, d.Name, fmtTime(d.CreatedAt.UTC())); err != nil {
		return fmt.Errorf("create device %q: %w", d.Name, err)
	}
	return nil
}

// GetDevice implements Store.
func (s *SQLiteStore) GetDevice(ctx context.Context, id string) (domain.ClientDevice, error) {
	return s.loadDevice(ctx, `SELECT id, token, name, created_at FROM client_devices WHERE id = ?`, id)
}

// GetDeviceByToken implements Store.
//
// An equality lookup on the UNIQUE(token) index, not a constant-time scan. What
// the B-tree walk can leak through timing is where a guess sorts relative to
// real tokens — not their bytes — against 128 random bits and a per-IP limiter
// that locks a caller out after ten misses; a constant-time scan would load
// every token of the fleet per request and buy nothing measurable.
func (s *SQLiteStore) GetDeviceByToken(ctx context.Context, token string) (domain.ClientDevice, error) {
	return s.loadDevice(ctx, `SELECT id, token, name, created_at FROM client_devices WHERE token = ?`, token)
}

func (s *SQLiteStore) loadDevice(ctx context.Context, q, arg string) (domain.ClientDevice, error) {
	var (
		d         domain.ClientDevice
		createdAt string
	)
	err := s.db.QueryRowContext(ctx, q, arg).Scan(&d.ID, &d.Token, &d.Name, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ClientDevice{}, ErrNotFound
	}
	if err != nil {
		return domain.ClientDevice{}, fmt.Errorf("load device: %w", err)
	}
	d.CreatedAt = parseTime(createdAt)
	creds, err := s.deviceCredentials(ctx, d.ID)
	if err != nil {
		return domain.ClientDevice{}, err
	}
	d.Credentials = creds[d.ID]
	return d, nil
}

// deviceCredentials returns attached credentials grouped by device ("" = every
// device), ordered by master then kind so a page and a profile list them alike.
func (s *SQLiteStore) deviceCredentials(ctx context.Context, deviceID string) (map[string][]domain.DeviceCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT device_id, kind, master_id, ref, name FROM (
			SELECT device_id, 'awg' AS kind, master_id, id AS ref, name FROM client_wg_credentials WHERE device_id IS NOT NULL
			UNION ALL
			SELECT device_id, 'vless' AS kind, master_id, name AS ref, name FROM client_vless_credentials WHERE device_id IS NOT NULL
		) WHERE (? = '' OR device_id = ?) ORDER BY device_id, master_id, kind`, deviceID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("list device credentials: %w", err)
	}
	defer rows.Close()
	out := make(map[string][]domain.DeviceCredential)
	for rows.Next() {
		var (
			dev, kind string
			c         domain.DeviceCredential
		)
		if err := rows.Scan(&dev, &kind, &c.MasterID, &c.Ref, &c.Name); err != nil {
			return nil, fmt.Errorf("scan device credential: %w", err)
		}
		c.Kind = domain.CredentialKind(kind)
		out[dev] = append(out[dev], c)
	}
	return out, rows.Err()
}

// ListDevices implements Store.
func (s *SQLiteStore) ListDevices(ctx context.Context) ([]domain.ClientDevice, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, token, name, created_at FROM client_devices ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	var out []domain.ClientDevice
	for rows.Next() {
		var (
			d         domain.ClientDevice
			createdAt string
		)
		if err := rows.Scan(&d.ID, &d.Token, &d.Name, &createdAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan device: %w", err)
		}
		d.CreatedAt = parseTime(createdAt)
		out = append(out, d)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	// Second query only after the first cursor is closed: the pool holds ONE
	// connection, and a nested query would wait on itself.
	creds, err := s.deviceCredentials(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Credentials = creds[out[i].ID]
	}
	return out, nil
}

// RenameDevice implements Store.
func (s *SQLiteStore) RenameDevice(ctx context.Context, id, name string) error {
	if name == "" {
		return errors.New("store: device name is required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE client_devices SET name=? WHERE id=?`, name, id)
	if err != nil {
		return fmt.Errorf("rename device %q: %w", id, err)
	}
	return requireAffected(res)
}

// RotateDeviceToken implements Store.
func (s *SQLiteStore) RotateDeviceToken(ctx context.Context, id, token string) error {
	if token == "" {
		return errors.New("store: device token is required")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE client_devices SET token=? WHERE id=?`, token, id)
	if err != nil {
		return fmt.Errorf("rotate device token %q: %w", id, err)
	}
	return requireAffected(res)
}

// DeleteDevice implements Store. Credentials are unlinked by the foreign key;
// their personal links were retired when they joined, and stay retired.
func (s *SQLiteStore) DeleteDevice(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM client_devices WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("delete device %q: %w", id, err)
	}
	return requireAffected(res)
}

// AttachCredential implements Store.
func (s *SQLiteStore) AttachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref, deviceID string) error {
	q, err := stmtsFor(kind)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("attach credential: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_devices WHERE id=?`, deviceID).Scan(&n); err != nil {
		return fmt.Errorf("attach credential: device: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	var current sql.NullString
	err = tx.QueryRowContext(ctx, q.readDevice, masterID, ref).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("attach credential: read: %w", err)
	}
	switch {
	case current.Valid && current.String == deviceID:
		return tx.Commit() // replaying the write changes nothing
	case current.Valid:
		return ErrCredentialAttached
	}
	if _, err := tx.ExecContext(ctx, q.attach, deviceID, masterID, ref); err != nil {
		if isDeviceSlotViolation(err) {
			return ErrDeviceSlotTaken
		}
		return fmt.Errorf("attach credential: %w", err)
	}
	return tx.Commit()
}

// DetachCredential implements Store. newToken is minted by the caller and used
// only when the device's token IS this credential's ID — a migrated device. Such
// a device must not keep answering on the ID of a credential it no longer holds
// (it would answer "paused" on a link the operator thinks belongs to nobody), so
// its token rotates in the same transaction.
func (s *SQLiteStore) DetachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref, newToken string) error {
	q, err := stmtsFor(kind)
	if err != nil {
		return err
	}
	if newToken == "" {
		return errors.New("store: a replacement token is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("detach credential: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var dev sql.NullString
	err = tx.QueryRowContext(ctx, q.readDevice, masterID, ref).Scan(&dev)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("detach credential: read: %w", err)
	}
	if _, err := tx.ExecContext(ctx, q.detach, masterID, ref); err != nil {
		return fmt.Errorf("detach credential: %w", err)
	}
	if kind == domain.CredentialAWG && dev.Valid {
		if _, err := tx.ExecContext(ctx,
			`UPDATE client_devices SET token=? WHERE id=? AND token=?`, newToken, dev.String, ref); err != nil {
			return fmt.Errorf("detach credential: rotate token: %w", err)
		}
	}
	return tx.Commit()
}

// isDeviceSlotViolation recognises the partial unique index's refusal. The
// driver reports it as a message naming the columns, as the panel's
// isUniqueViolation reads name/address collisions.
func isDeviceSlotViolation(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") && strings.Contains(msg, "device_id")
}

// AddWGClientToDevice implements Store: credential, device link and retired
// personal link in ONE insert — no replica can observe one without the others.
func (s *SQLiteStore) AddWGClientToDevice(ctx context.Context, masterID string, c domain.WGClient, deviceID string) error {
	if deviceID == "" {
		return errors.New("store: device is required")
	}
	return s.addWGClient(ctx, masterID, c, deviceID)
}

// AddVLESSClientToDevice implements Store. A plain INSERT, unlike
// AddVLESSClient's upsert: a device-bound issue must not quietly re-key a
// same-named credential someone else is using. createdAt comes from the caller:
// domain.VLESSClient travels in NodeSpec over the wire, so the time rides as a
// parameter instead of a field.
func (s *SQLiteStore) AddVLESSClientToDevice(ctx context.Context, masterID string, c domain.VLESSClient, deviceID string, createdAt time.Time) error {
	switch {
	case masterID == "" || c.Name == "" || c.UUID == "" || deviceID == "":
		return errors.New("store: master ID, client name, UUID and device are required")
	case createdAt.IsZero():
		return errors.New("store: createdAt is required (the caller stamps it, not the store)")
	}
	if _, err := s.GetNode(ctx, masterID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO client_vless_credentials (master_id, name, uuid, short_id, created_at, device_id)
		 VALUES (?,?,?,?,?,?)`,
		masterID, c.Name, c.UUID, c.ShortID, fmtTime(createdAt.UTC()), deviceID); err != nil {
		if isDeviceSlotViolation(err) {
			return ErrDeviceSlotTaken
		}
		return fmt.Errorf("add vless client %q for %q: %w", c.Name, masterID, err)
	}
	return nil
}

// FindUnattachedWGClient implements Store: the legacy portal lookup, ONE query
// on idx_client_wg_id across every master. Only a credential that has never
// belonged to a device qualifies.
func (s *SQLiteStore) FindUnattachedWGClient(ctx context.Context, id string) (string, domain.WGClient, error) {
	var (
		master    string
		c         domain.WGClient
		enabled   int
		createdAt string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT master_id, id, name, address, public_key, private_key, preshared_key, enabled, created_at
		 FROM client_wg_credentials WHERE id=? AND device_id IS NULL AND legacy_link_retired=0`, id).Scan(
		&master, &c.ID, &c.Name, &c.Address, &c.PublicKey, &c.PrivateKey, &c.PresharedKey, &enabled, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", domain.WGClient{}, ErrNotFound
	}
	if err != nil {
		return "", domain.WGClient{}, fmt.Errorf("find wg client %q: %w", id, err)
	}
	c.Enabled = enabled != 0
	c.CreatedAt = parseTime(createdAt)
	return master, c, nil
}
