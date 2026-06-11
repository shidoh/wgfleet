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
}
