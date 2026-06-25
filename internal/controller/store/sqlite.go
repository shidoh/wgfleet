package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite driver, registered as "sqlite"

	"github.com/shidoh/wgfleet/internal/domain"
)

// timeLayout is the on-disk representation for timestamps. RFC3339Nano sorts
// lexicographically in the same order as chronologically, which keeps ORDER BY
// honest.
const timeLayout = time.RFC3339Nano

// SQLiteStore is the modernc.org/sqlite-backed Store. It uses no CGO.
type SQLiteStore struct {
	db  *sql.DB
	now func() time.Time // injectable clock for deterministic tests
}

var _ Store = (*SQLiteStore)(nil)

// Open opens (creating if needed) the sqlite database at path and applies
// migrations. Use ":memory:" for ephemeral test stores.
func Open(path string) (*SQLiteStore, error) {
	// WAL + a busy timeout keep concurrent reconcile reporters from tripping
	// over each other; foreign_keys(1) enables the ON DELETE CASCADE above.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, err)
	}
	// modernc/sqlite is a single-writer engine; cap connections so writes
	// serialize cleanly instead of returning SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies any migrations newer than the database's recorded schema
// version, tracked in SQLite's PRAGMA user_version. This makes the migration
// list properly append-only: non-idempotent statements (ALTER TABLE ADD COLUMN)
// run exactly once. A pre-versioning database reports user_version 0; its first
// two migrations are CREATE ... IF NOT EXISTS, so re-running them is harmless and
// the upgrade is seamless.
func (s *SQLiteStore) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for i := version; i < len(migrations); i++ {
		if _, err := s.db.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i, err)
		}
	}
	// PRAGMA user_version does not accept bound parameters; len(migrations) is a
	// trusted in-code constant, so the format is safe.
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", len(migrations))); err != nil {
		return fmt.Errorf("set schema version: %w", err)
	}
	return nil
}

// Close implements Store.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// UpsertNode implements Store.
func (s *SQLiteStore) UpsertNode(ctx context.Context, n domain.Node) error {
	if n.ID == "" {
		return errors.New("store: node ID is required")
	}
	now := s.now().UTC()

	// Preserve the original created_at on update via COALESCE against the
	// existing row; new rows fall back to now.
	const q = `
		INSERT INTO nodes (
			id, name, role, region, mgmt_addr, public_ip, public_key, reality_public_key, state,
			drain, decommission, last_error, ssh_host, ssh_port, ssh_user, ssh_key_path,
			agent_version, wire_version,
			created_at, updated_at, last_seen
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, role=excluded.role, region=excluded.region,
			mgmt_addr=excluded.mgmt_addr, public_ip=excluded.public_ip,
			public_key=excluded.public_key, reality_public_key=excluded.reality_public_key,
			state=excluded.state,
			drain=excluded.drain, decommission=excluded.decommission,
			last_error=excluded.last_error,
			ssh_host=excluded.ssh_host, ssh_port=excluded.ssh_port,
			ssh_user=excluded.ssh_user, ssh_key_path=excluded.ssh_key_path,
			agent_version=excluded.agent_version, wire_version=excluded.wire_version,
			updated_at=excluded.updated_at, last_seen=excluded.last_seen`
	_, err := s.db.ExecContext(ctx, q,
		n.ID, n.Name, string(n.Role), n.Region, n.MgmtAddr, n.PublicIP,
		n.PublicKey, n.RealityPublicKey, string(n.State), boolToInt(n.Drain), boolToInt(n.Decommission), n.LastError,
		n.SSH.Host, n.SSH.Port, n.SSH.User, n.SSH.KeyPath,
		n.AgentVersion, n.WireVersion,
		fmtTime(orDefault(n.CreatedAt, now)), fmtTime(now), fmtTime(n.LastSeen),
	)
	if err != nil {
		return fmt.Errorf("upsert node %q: %w", n.ID, err)
	}
	return nil
}

// GetNode implements Store.
func (s *SQLiteStore) GetNode(ctx context.Context, id string) (domain.Node, error) {
	const q = `SELECT id, name, role, region, mgmt_addr, public_ip, public_key, reality_public_key,
		state, drain, decommission, last_error, ssh_host, ssh_port, ssh_user, ssh_key_path,
		agent_version, wire_version, created_at, updated_at, last_seen FROM nodes WHERE id = ?`
	return scanNode(s.db.QueryRowContext(ctx, q, id))
}

// ListNodes implements Store.
func (s *SQLiteStore) ListNodes(ctx context.Context) ([]domain.Node, error) {
	const q = `SELECT id, name, role, region, mgmt_addr, public_ip, public_key, reality_public_key,
		state, drain, decommission, last_error, ssh_host, ssh_port, ssh_user, ssh_key_path,
		agent_version, wire_version, created_at, updated_at, last_seen FROM nodes ORDER BY name`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	var nodes []domain.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// DeleteNode implements Store.
func (s *SQLiteStore) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete node %q: %w", id, err)
	}
	return requireAffected(res)
}

// SetNodeState implements Store.
func (s *SQLiteStore) SetNodeState(ctx context.Context, id string, state domain.NodeState, lastErr string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET state=?, last_error=?, updated_at=? WHERE id=?`,
		string(state), lastErr, fmtTime(s.now().UTC()), id)
	if err != nil {
		return fmt.Errorf("set state for %q: %w", id, err)
	}
	return requireAffected(res)
}

// SetNodeDrain implements Store.
func (s *SQLiteStore) SetNodeDrain(ctx context.Context, id string, drain bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET drain=?, updated_at=? WHERE id=?`,
		boolToInt(drain), fmtTime(s.now().UTC()), id)
	if err != nil {
		return fmt.Errorf("set drain for %q: %w", id, err)
	}
	return requireAffected(res)
}

// SetNodeDecommission implements Store.
func (s *SQLiteStore) SetNodeDecommission(ctx context.Context, id string, decommission bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET decommission=?, updated_at=? WHERE id=?`,
		boolToInt(decommission), fmtTime(s.now().UTC()), id)
	if err != nil {
		return fmt.Errorf("set decommission for %q: %w", id, err)
	}
	return requireAffected(res)
}

// SetNodePublicKey implements Store.
func (s *SQLiteStore) SetNodePublicKey(ctx context.Context, id, publicKey string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET public_key=?, updated_at=? WHERE id=?`,
		publicKey, fmtTime(s.now().UTC()), id)
	if err != nil {
		return fmt.Errorf("set public key for %q: %w", id, err)
	}
	return requireAffected(res)
}

// SetNodeRealityKey implements Store: records the exit's REALITY x25519 public
// key (ADR-0025), separate from the WireGuard public_key.
func (s *SQLiteStore) SetNodeRealityKey(ctx context.Context, id, publicKey string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nodes SET reality_public_key=?, updated_at=? WHERE id=?`,
		publicKey, fmtTime(s.now().UTC()), id)
	if err != nil {
		return fmt.Errorf("set reality key for %q: %w", id, err)
	}
	return requireAffected(res)
}

// RecordStatus implements Store.
func (s *SQLiteStore) RecordStatus(ctx context.Context, st domain.NodeStatus) error {
	if st.NodeID == "" {
		return errors.New("store: status NodeID is required")
	}
	checks, err := json.Marshal(st.Checks)
	if err != nil {
		return fmt.Errorf("marshal checks: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin status tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO node_status (node_id, state, reported_at, last_handshake,
			egress_ip, reconcile_error, checks_json)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET
			state=excluded.state, reported_at=excluded.reported_at,
			last_handshake=excluded.last_handshake, egress_ip=excluded.egress_ip,
			reconcile_error=excluded.reconcile_error, checks_json=excluded.checks_json`,
		st.NodeID, string(st.State), fmtTime(orDefault(st.ReportedAt, s.now().UTC())),
		fmtTime(st.LastHandshake), st.EgressIP, st.ReconcileError, string(checks),
	); err != nil {
		return fmt.Errorf("record status for %q: %w", st.NodeID, err)
	}
	// Stamp last_seen on the node so the controller can detect silent agents.
	if _, err := tx.ExecContext(ctx,
		`UPDATE nodes SET last_seen=? WHERE id=?`,
		fmtTime(s.now().UTC()), st.NodeID); err != nil {
		return fmt.Errorf("stamp last_seen for %q: %w", st.NodeID, err)
	}
	return tx.Commit()
}

// GetStatus implements Store.
func (s *SQLiteStore) GetStatus(ctx context.Context, id string) (domain.NodeStatus, error) {
	const q = `SELECT node_id, state, reported_at, last_handshake, egress_ip,
		reconcile_error, checks_json FROM node_status WHERE node_id = ?`
	var (
		st                                domain.NodeStatus
		stateS, reportedAt, lastHandshake string
		checksJSON                        string
	)
	err := s.db.QueryRowContext(ctx, q, id).Scan(
		&st.NodeID, &stateS, &reportedAt, &lastHandshake,
		&st.EgressIP, &st.ReconcileError, &checksJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NodeStatus{}, ErrNotFound
	}
	if err != nil {
		return domain.NodeStatus{}, fmt.Errorf("get status %q: %w", id, err)
	}
	st.State = domain.NodeState(stateS)
	st.ReportedAt = parseTime(reportedAt)
	st.LastHandshake = parseTime(lastHandshake)
	if err := json.Unmarshal([]byte(checksJSON), &st.Checks); err != nil {
		return domain.NodeStatus{}, fmt.Errorf("unmarshal checks for %q: %w", id, err)
	}
	return st, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(row rowScanner) (domain.Node, error) {
	var (
		n                          domain.Node
		roleS, stateS              string
		drain, decommission        int
		createdAt, updatedAt, seen string
	)
	err := row.Scan(
		&n.ID, &n.Name, &roleS, &n.Region, &n.MgmtAddr, &n.PublicIP, &n.PublicKey, &n.RealityPublicKey,
		&stateS, &drain, &decommission, &n.LastError, &n.SSH.Host, &n.SSH.Port, &n.SSH.User, &n.SSH.KeyPath,
		&n.AgentVersion, &n.WireVersion,
		&createdAt, &updatedAt, &seen,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Node{}, ErrNotFound
	}
	if err != nil {
		return domain.Node{}, fmt.Errorf("scan node: %w", err)
	}
	n.Role = domain.Role(roleS)
	n.State = domain.NodeState(stateS)
	n.Drain = drain != 0
	n.Decommission = decommission != 0
	n.CreatedAt = parseTime(createdAt)
	n.UpdatedAt = parseTime(updatedAt)
	n.LastSeen = parseTime(seen)
	return n, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func requireAffected(res sql.Result) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func orDefault(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t
}
