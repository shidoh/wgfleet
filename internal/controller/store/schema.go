package store

// migrations are applied in order at Open time. Each entry is idempotent
// (IF NOT EXISTS), so re-opening an existing database is a no-op. When the
// schema evolves, append new statements; never edit an applied one.
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS nodes (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL,
		role         TEXT NOT NULL,
		region       TEXT NOT NULL DEFAULT '',
		mgmt_addr    TEXT NOT NULL DEFAULT '',
		public_ip    TEXT NOT NULL DEFAULT '',
		public_key   TEXT NOT NULL DEFAULT '',
		state        TEXT NOT NULL,
		drain        INTEGER NOT NULL DEFAULT 0,
		decommission INTEGER NOT NULL DEFAULT 0,
		last_error   TEXT NOT NULL DEFAULT '',
		ssh_host     TEXT NOT NULL DEFAULT '',
		ssh_port     INTEGER NOT NULL DEFAULT 0,
		ssh_user     TEXT NOT NULL DEFAULT '',
		ssh_key_path TEXT NOT NULL DEFAULT '',
		created_at   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		last_seen    TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name)`,
	`CREATE TABLE IF NOT EXISTS node_status (
		node_id         TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
		state           TEXT NOT NULL,
		reported_at     TEXT NOT NULL,
		last_handshake  TEXT NOT NULL DEFAULT '',
		egress_ip       TEXT NOT NULL DEFAULT '',
		reconcile_error TEXT NOT NULL DEFAULT '',
		checks_json     TEXT NOT NULL DEFAULT '[]'
	)`,
	// v3: record the agent's reported build + wire version for skew visibility.
	`ALTER TABLE nodes ADD COLUMN agent_version TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE nodes ADD COLUMN wire_version INTEGER NOT NULL DEFAULT 0`,
	// v4: the exit's REALITY x25519 public key (ADR-0025), published separately
	// from the WireGuard public_key; the master's vless proxy peers it.
	`ALTER TABLE nodes ADD COLUMN reality_public_key TEXT NOT NULL DEFAULT ''`,
	// v5: the operator's live UI override of the active master↔exit transport
	// (ADR-0025); empty ⇒ use the manifest's active_transport.
	`ALTER TABLE nodes ADD COLUMN active_transport TEXT NOT NULL DEFAULT ''`,
	// v6: master's per-exit tunnel health (mihomo proxy liveness), JSON like checks.
	`ALTER TABLE node_status ADD COLUMN exit_health_json TEXT NOT NULL DEFAULT '[]'`,
	// v7: single-row web-panel admin credential. id is pinned to 1 so the table
	// holds exactly one account (single-user panel); SetAuthCredential upserts it.
	`CREATE TABLE IF NOT EXISTS auth (
		id             INTEGER PRIMARY KEY CHECK (id = 1),
		username       TEXT NOT NULL,
		password_hash  TEXT NOT NULL,
		session_secret BLOB NOT NULL,
		updated_at     TEXT NOT NULL
	)`,
	// v8: per-tunnel WireGuard public keys (ADR-0030). The master publishes one
	// identity per master↔exit tunnel instead of reusing nodes.public_key for all of
	// them, so two exits can no longer be correlated by comparing one string and a
	// single exit can be re-keyed in isolation. A separate table rather than more
	// nodes columns because the row count is per (node, tunnel), not per node; the
	// primary key makes re-publishing the same tunnel an idempotent upsert. Rows
	// cascade with the owning node so a deleted master leaves no orphan keys.
	// nodes.public_key stays populated and authoritative for the legacy shared
	// identity — this table is strictly additive.
	`CREATE TABLE IF NOT EXISTS node_tunnel_keys (
		node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
		tunnel     TEXT NOT NULL,
		public_key TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		PRIMARY KEY (node_id, tunnel)
	)`,
}
