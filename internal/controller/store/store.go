// Package store persists controller state: the node inventory, the public-key
// registry (key broker), and the latest status report per node. It follows the
// repository pattern — callers depend on the Store interface, not on sqlite —
// so the backend can be swapped (or mocked in tests) without touching them.
package store

import (
	"context"
	"errors"

	"github.com/shidoh/wgfleet/internal/domain"
)

// ErrNotFound is returned when a requested node or status does not exist.
var ErrNotFound = errors.New("store: not found")

// Store is the controller's persistence boundary. All methods take a context so
// callers can cancel slow queries; implementations must honor it.
type Store interface {
	// UpsertNode inserts or replaces a node by ID. It sets UpdatedAt and, on
	// first insert, CreatedAt.
	UpsertNode(ctx context.Context, n domain.Node) error

	// GetNode returns the node with the given ID, or ErrNotFound.
	GetNode(ctx context.Context, id string) (domain.Node, error)

	// ListNodes returns all nodes, ordered by name. This is also the source for
	// the key broker: every node carries its registered PublicKey.
	ListNodes(ctx context.Context) ([]domain.Node, error)

	// DeleteNode removes a node and its status, and retires its id: a later
	// Register under that id is refused until Readmit. Returns ErrNotFound if absent.
	DeleteNode(ctx context.Context, id string) error
	// Retired reports whether an id was deleted and not since re-admitted.
	Retired(ctx context.Context, id string) (bool, error)
	// Readmit lifts the retirement of an id — the explicit operator act
	// (provisioning) that brings a deleted node back. Absent id ⇒ no-op.
	Readmit(ctx context.Context, id string) error

	// SetNodeState transitions a node's lifecycle state and records lastErr
	// (empty string clears it). Returns ErrNotFound if the node is absent.
	SetNodeState(ctx context.Context, id string, state domain.NodeState, lastErr string) error

	// SetNodeDrain sets/clears a node's drain flag (take it out of / back into
	// the load balancer). Returns ErrNotFound if the node is absent.
	SetNodeDrain(ctx context.Context, id string, drain bool) error

	// SetNodeDecommission sets/clears a node's decommission flag (tell the agent
	// to tear the node down). Returns ErrNotFound if the node is absent.
	SetNodeDecommission(ctx context.Context, id string, decommission bool) error

	// SetNodePublicKey registers a node's WireGuard public key (key-broker
	// model: the controller only ever stores pubkeys). Returns ErrNotFound if
	// the node is absent.
	SetNodePublicKey(ctx context.Context, id, publicKey string) error

	// SetNodeTunnelKey registers one PER-TUNNEL WireGuard public key for a node
	// (ADR-0030): the master's dedicated identity for the tunnel named by tunnel
	// (the exit's node name). Idempotent — re-publishing the same tunnel replaces
	// the key. Returns ErrNotFound if the node is absent.
	SetNodeTunnelKey(ctx context.Context, id, tunnel, publicKey string) error

	// ListNodeTunnelKeys returns a node's per-tunnel WireGuard public keys keyed by
	// tunnel name. An unknown node yields an empty map, not ErrNotFound: callers
	// render peers from whatever is registered so far and converge (the same
	// tolerance the unsuffixed key lookup has).
	ListNodeTunnelKeys(ctx context.Context, id string) (map[string]string, error)

	// SetNodeRealityKey registers an exit's REALITY x25519 public key (ADR-0025),
	// stored separately from the WireGuard key. Returns ErrNotFound if the node
	// is absent.
	SetNodeRealityKey(ctx context.Context, id, publicKey string) error

	// SetNodeActiveTransport overrides the active master↔exit transport for an exit
	// (ADR-0025); empty clears it back to the manifest default. Returns ErrNotFound
	// if the node is absent.
	SetNodeActiveTransport(ctx context.Context, id string, transport domain.MasterTransport) error

	// SetNodeClientVlessKey registers the master's CLIENT-FACING REALITY x25519
	// public key, stored separately from the WireGuard and exit-reality keys.
	// Returns ErrNotFound if the node is absent.
	SetNodeClientVlessKey(ctx context.Context, id, publicKey string) error

	// SetNodeClientWGKey records the master's CLIENT-FACING WireGuard public key
	// (the interface end users dial once the agent owns it), separate from the
	// node's fleet-internal public key. Returns ErrNotFound if the node is absent.
	SetNodeClientWGKey(ctx context.Context, id, publicKey string) error

	// ListVLESSClients returns a master's issued VLESS client credentials, ordered
	// by name. An unknown master yields an empty slice, not ErrNotFound.
	ListVLESSClients(ctx context.Context, masterID string) ([]domain.VLESSClient, error)

	// AddVLESSClient issues one VLESS client credential for a master (idempotent on
	// (master, name): re-issuing the same name replaces its UUID/short-id). Returns
	// ErrNotFound if the master is absent.
	AddVLESSClient(ctx context.Context, masterID string, c domain.VLESSClient) error

	// RevokeVLESSClient removes a master's VLESS client credential by name. Returns
	// ErrNotFound if the (master, name) pair is absent.
	RevokeVLESSClient(ctx context.Context, masterID, name string) error

	// ListWGClients returns a master's issued client-facing WireGuard credentials,
	// ordered by name. An unknown master yields an empty slice, not ErrNotFound.
	// The returned records carry the clients' PRIVATE keys — the controller renders
	// their configs — so callers must not pass them anywhere node-bound; project
	// them through domain.PeersOf first.
	ListWGClients(ctx context.Context, masterID string) ([]domain.WGClient, error)

	// AddWGClient stores one already-minted client-facing WireGuard credential.
	// It is deliberately NOT a mint: the caller generates the keypair and allocates
	// the address before calling, so the write is a deterministic record of a
	// decision already made (ADR-0027's FSM replays this write on every replica).
	// Returns ErrNotFound if the master is absent, and an error when the name or
	// the address is already taken on that master.
	AddWGClient(ctx context.Context, masterID string, c domain.WGClient) error

	// SetWGClientEnabled mutes or unmutes a credential: a muted client leaves the
	// interface while its config stays valid. Returns ErrNotFound if the
	// (master, client) pair is absent.
	SetWGClientEnabled(ctx context.Context, masterID, clientID string, enabled bool) error

	// RenameWGClient changes a credential's operator-facing label, leaving its
	// identity, keys and address untouched. Returns ErrNotFound if the
	// (master, client) pair is absent.
	RenameWGClient(ctx context.Context, masterID, clientID, name string) error

	// RemoveWGClient revokes a credential outright. Returns ErrNotFound if the
	// (master, client) pair is absent.
	RemoveWGClient(ctx context.Context, masterID, clientID string) error

	// RecordStatus stores the latest status report for a node, overwriting any
	// previous report, and stamps the node's LastSeen.
	RecordStatus(ctx context.Context, s domain.NodeStatus) error

	// GetStatus returns the latest status for a node, or ErrNotFound.
	GetStatus(ctx context.Context, id string) (domain.NodeStatus, error)

	// AuthConfigured reports whether the single web-panel admin credential exists.
	AuthConfigured(ctx context.Context) (bool, error)
	// GetAuth returns the admin credential, or ErrNotFound when unset.
	GetAuth(ctx context.Context) (domain.AuthRecord, error)
	// SetAuthCredential upserts the admin account (first-run setup / CLI reset),
	// setting username, password hash, and session signing secret.
	SetAuthCredential(ctx context.Context, username, passwordHash string, sessionSecret []byte) error
	// SetAuthPassword changes the password and rotates the session secret in one
	// write (invalidating other sessions). Returns ErrNotFound if no row exists.
	SetAuthPassword(ctx context.Context, passwordHash string, sessionSecret []byte) error

	// Close releases the underlying database handle.
	Close() error
}
