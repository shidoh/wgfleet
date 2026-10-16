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
	// v9: the master's CLIENT-FACING REALITY x25519 public key (the client VLESS
	// inbound), published separately from the exit reality_public_key; a co-located
	// controller+master node carries both. Used to build clients' vless:// links.
	`ALTER TABLE nodes ADD COLUMN client_vless_public_key TEXT NOT NULL DEFAULT ''`,
	// v10: per-client VLESS credentials issued through the Web UI (UUID + REALITY
	// short-id + label). A separate table because the row count is per (master,
	// client), not per node; rows cascade with the owning master. Not secret — the
	// REALITY private key stays on the master — so the controller enumerates these
	// to render the inbound's clients list and to build/revoke vless:// links.
	`CREATE TABLE IF NOT EXISTS client_vless_credentials (
		master_id  TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
		name       TEXT NOT NULL,
		uuid       TEXT NOT NULL,
		short_id   TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		PRIMARY KEY (master_id, name)
	)`,
	// v11: per-client WireGuard credentials for the CLIENT-FACING interface — the
	// leg that used to belong to wg-easy. Unlike client_vless_credentials these
	// rows hold a SECRET: the client's private key, which the controller generates
	// so it can re-render the .conf and the QR at any time. The file is 0600, the
	// value is redacted in plan/UI output and travels in the age backup.
	//
	// The key is (master_id, id), not (master_id, name): identity must survive a
	// rename (ADR-0028), and under multi-master the same person holds one
	// credential per gateway (ADR-0027). The two UNIQUE constraints put the
	// operator-facing invariants in the schema, where no code path can bypass
	// them: one label per master, and never two clients on one tunnel address.
	`CREATE TABLE IF NOT EXISTS client_wg_credentials (
		master_id     TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
		id            TEXT NOT NULL,
		name          TEXT NOT NULL,
		address       TEXT NOT NULL,
		public_key    TEXT NOT NULL,
		private_key   TEXT NOT NULL,
		preshared_key TEXT NOT NULL DEFAULT '',
		enabled       INTEGER NOT NULL DEFAULT 1,
		created_at    TEXT NOT NULL,
		PRIMARY KEY (master_id, id),
		UNIQUE (master_id, name),
		UNIQUE (master_id, address)
	)`,
	// v12: the master's CLIENT-FACING WireGuard public key — the identity of the
	// interface end users dial once the agent owns it. Published by the agent like
	// the client-vless REALITY key; the controller needs it to render the [Peer]
	// block of every client config it hands out.
	`ALTER TABLE nodes ADD COLUMN client_wg_public_key TEXT NOT NULL DEFAULT ''`,
	// v13: the master's live client peers (public key, endpoint, handshake age,
	// counters) as the agent last reported them. Stored as JSON beside the other
	// per-report blobs: the shape is the agent's to change, and the controller only
	// ever reads it back whole to render a page.
	`ALTER TABLE node_status ADD COLUMN client_peers_json TEXT NOT NULL DEFAULT '[]'`,
	// v14: nodes the operator deleted. Deleting a row was not the end of a node:
	// its certificate is not revoked, so an agent that still reached the controller
	// re-registered on its next pass and auto-created the row again — the exit an
	// operator had just deleted was back on the fleet page, back in the master's
	// tunnel list, and back in front of the namespace readiness gate, within a
	// minute (a tester's fleet, 2026-09-07). A retired id is refused at Register
	// until an explicit Provision re-admits it.
	`CREATE TABLE IF NOT EXISTS retired_nodes (
		id         TEXT PRIMARY KEY,
		retired_at TEXT NOT NULL
	)`,
	// v15: the exit's LIFELINE WireGuard public key — the identity of the reserve
	// client-facing interface (awgl0) an exit may carry, published separately from
	// public_key (the master↔exit tunnel identity) and client_wg_public_key (the
	// master's own client leg).
	`ALTER TABLE nodes ADD COLUMN lifeline_public_key TEXT NOT NULL DEFAULT ''`,
	// v16: client DEVICES (ADR-0035) — one physical device of one person, the unit
	// a mihomo subscription is issued for. Fleet-wide: credentials stay per master
	// and point here, so one profile can carry every gateway the device holds a
	// credential on. id is internal and stable (the panel links to it); token is
	// the portal secret and rotates alone, so a leaked link is cut off without the
	// device changing identity.
	`CREATE TABLE IF NOT EXISTS client_devices (
		id         TEXT PRIMARY KEY,
		token      TEXT NOT NULL UNIQUE,
		name       TEXT NOT NULL UNIQUE,
		created_at TEXT NOT NULL
	)`,
	// v17/v18: the credential points at its device, never the reverse — a
	// credential without a device is ordinary, and deleting a device only unlinks
	// (SET NULL): revoking stays an explicit act on the credential. SQLite admits a
	// REFERENCES column via ADD COLUMN only with a NULL default — the shape wanted.
	`ALTER TABLE client_wg_credentials ADD COLUMN device_id TEXT REFERENCES client_devices(id) ON DELETE SET NULL`,
	`ALTER TABLE client_vless_credentials ADD COLUMN device_id TEXT REFERENCES client_devices(id) ON DELETE SET NULL`,
	// v19/v20: at most one credential of each kind per device per master, held by
	// the schema where no code path can bypass it. Partial, so the unattached
	// majority is not constrained at all.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_client_wg_device_master
		ON client_wg_credentials(device_id, master_id) WHERE device_id IS NOT NULL`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_client_vless_device_master
		ON client_vless_credentials(device_id, master_id) WHERE device_id IS NOT NULL`,
	// v21: one-shot data migrations that must never run twice. Not user_version:
	// that counts SCHEMA steps and is replayed by alreadyApplied after a rollback,
	// while a data step replayed would re-wrap credentials the operator left
	// without a device on purpose.
	`CREATE TABLE IF NOT EXISTS store_markers (
		name       TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`,
	// v22: a credential's own portal link (/c/{id}) dies for good the first time
	// the credential joins a device. Without it, deleting a migrated device —
	// whose token IS the credential ID — or detaching the credential would make
	// the ID a working link again: a link the operator believed cut off, handing
	// out a private key.
	`ALTER TABLE client_wg_credentials ADD COLUMN legacy_link_retired INTEGER NOT NULL DEFAULT 0`,
	// v23: the legacy lookup is by credential ID alone, across every master; the
	// primary key is (master_id, id) and cannot serve it.
	`CREATE INDEX IF NOT EXISTS idx_client_wg_id ON client_wg_credentials(id)`,
	// v24: the endpoint an exit's awg0 holds for the master (exit-initiated AWG
	// flow). The controller arms the master's gate only once it equals the pinned
	// address, so the exit's last report has to survive a controller restart.
	`ALTER TABLE node_status ADD COLUMN awg_master_endpoint TEXT NOT NULL DEFAULT ''`,
	// v25: the generation of an exit-initiated tunnel's pinned master port. A path
	// filter can poison or freeze the pinned flow for good; the controller then
	// moves to the next generation and the exit opens a fresh flow. Kept across
	// restarts: generation 0 again would hand the exit back the poisoned tuple.
	`CREATE TABLE IF NOT EXISTS awg_port_rotation (
		node_id    TEXT PRIMARY KEY,
		generation INTEGER NOT NULL,
		rotated_at TEXT NOT NULL
	)`,
	// v26: the pinned-port generation is a property of one master↔exit tunnel, not
	// of the exit: with several masters each has its own pinned address and its own
	// poisoned-flow history. The rows of awg_port_rotation, keyed by exit alone,
	// are carried over by AdoptAWGPortRotation — a data move is not a schema step
	// (see store_markers above), and the old table is left in place.
	`CREATE TABLE IF NOT EXISTS awg_pin_rotation (
		master_id  TEXT NOT NULL,
		exit_id    TEXT NOT NULL,
		generation INTEGER NOT NULL,
		rotated_at TEXT NOT NULL,
		PRIMARY KEY (master_id, exit_id)
	)`,
	// v27: an exit's per-master-peer report (StatusReport.master_peers, wire 13).
	`ALTER TABLE node_status ADD COLUMN master_peers_json TEXT NOT NULL DEFAULT '[]'`,
	// v28: the address an exit confirmed holding for one master, which of the
	// master's peers said so, and since when. The gate on the master is armed from
	// it, and a wire-13 exit's per-peer report is deliberately not sticky — so held
	// in memory alone, a controller restart followed by one pass that could not read
	// the interface disarmed the gate and had the master speak first on a filtered
	// path. since is the silence clock: it has to survive too, or a tunnel that was
	// already dead gets a fresh AWGRotateAfter on every restart.
	`CREATE TABLE IF NOT EXISTS awg_pin_confirmed (
		master_id TEXT NOT NULL,
		exit_id   TEXT NOT NULL,
		addr      TEXT NOT NULL,
		peer_key  TEXT NOT NULL,
		since     TEXT NOT NULL,
		PRIMARY KEY (master_id, exit_id)
	)`,
	// v29: the exits the throughput watchdog currently holds out of the load
	// balancer. Held in memory alone, a controller restart put every suspended
	// exit straight back into the group and pulled it again AutoSuspendAfter
	// later — two re-renders of each master's mihomo, each one a container restart
	// that drops every client connection.
	`CREATE TABLE IF NOT EXISTS exit_auto_suspend (
		exit_id TEXT PRIMARY KEY,
		since   TEXT NOT NULL
	)`,
	// v30: the master's REALITY PORTAL x25519 public key (ADR-0038) — the inbound
	// exits in the exit-initiated mode dial. Its own column: the client VLESS key
	// is handed to end users and rotates on a different schedule.
	`ALTER TABLE nodes ADD COLUMN reality_portal_public_key TEXT NOT NULL DEFAULT ''`,
	// v31: the VLESS id and short-id of an exit's bridge at a master's portal.
	// Random and stored, never derived from names: an id anyone can compute lets
	// one exit register under another's reverse tag and take its traffic.
	`CREATE TABLE IF NOT EXISTS reality_portal_ids (
		master_id  TEXT NOT NULL,
		exit_id    TEXT NOT NULL,
		uuid       TEXT NOT NULL,
		short_id   TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (master_id, exit_id)
	)`,
}

// MigrationCount is how many schema migrations this build knows. Exported so a
// caller can answer "is this database newer than me?" without opening it — the
// check --check-config needs, since opening would create and migrate.
func MigrationCount() int { return len(migrations) }
