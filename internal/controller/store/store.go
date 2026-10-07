// Package store persists controller state: the node inventory, the public-key
// registry (key broker), and the latest status report per node. It follows the
// repository pattern — callers depend on the Store interface, not on sqlite —
// so the backend can be swapped (or mocked in tests) without touching them.
package store

import (
	"context"
	"errors"
	"time"

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

	// SetNodeLifelineKey records the exit's LIFELINE interface WireGuard public
	// key (the reserve client-facing interface awgl0), separate from the node's
	// fleet-internal and ordinary client-facing keys. Returns ErrNotFound if the
	// node is absent.
	SetNodeLifelineKey(ctx context.Context, id, publicKey string) error

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

	// CreateDevice inserts one client device (ADR-0035). ID, Token and Name are
	// required and Name/Token are unique fleet-wide; CreatedAt is stamped by the
	// caller, never by the store.
	CreateDevice(ctx context.Context, d domain.ClientDevice) error

	// GetDevice returns a device by its internal, stable ID, with its attached
	// credentials. Returns ErrNotFound if absent.
	GetDevice(ctx context.Context, id string) (domain.ClientDevice, error)

	// GetDeviceByToken returns a device by its portal token, with its attached
	// credentials. Returns ErrNotFound if the token is unknown.
	GetDeviceByToken(ctx context.Context, token string) (domain.ClientDevice, error)

	// ListDevices returns every device, ordered by name, each with its attached
	// credentials.
	ListDevices(ctx context.Context) ([]domain.ClientDevice, error)

	// RenameDevice changes a device's operator-facing label. Returns ErrNotFound
	// if the device is absent.
	RenameDevice(ctx context.Context, id, name string) error

	// RotateDeviceToken replaces a device's portal token, cutting off anyone
	// holding the old one. Returns ErrNotFound if the device is absent.
	RotateDeviceToken(ctx context.Context, id, token string) error

	// DeleteDevice removes a device. Its credentials are unlinked (ON DELETE SET
	// NULL), not revoked — deleting a device is not the same act as revoking the
	// credentials it held. Returns ErrNotFound if the device is absent.
	DeleteDevice(ctx context.Context, id string) error

	// AttachCredential links an existing credential (kind, masterID, ref) to a
	// device. Returns ErrNotFound if the device or the credential is absent,
	// ErrDeviceSlotTaken if the device already holds a credential of this kind on
	// this master, and ErrCredentialAttached if the credential belongs to another
	// device. Attaching an AWG credential retires its personal link for good.
	AttachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref, deviceID string) error

	// DetachCredential unlinks a credential from its device without revoking it.
	// newToken is minted by the caller and used only when the device's token IS
	// this credential's ID (a migrated device): such a device rotates onto
	// newToken in the same transaction, so it stops answering on an ID it no
	// longer holds. Returns ErrNotFound if the credential is absent.
	DetachCredential(ctx context.Context, kind domain.CredentialKind, masterID, ref, newToken string) error

	// AddWGClientToDevice stores one already-minted client-facing WireGuard
	// credential already linked to a device, retiring its personal link in the
	// same write. Returns ErrNotFound if the master or the device is absent.
	AddWGClientToDevice(ctx context.Context, masterID string, c domain.WGClient, deviceID string) error

	// AddVLESSClientToDevice issues one VLESS client credential already linked to
	// a device. Unlike AddVLESSClient this is a plain insert: it must not
	// silently re-key a same-named credential someone else is using. Returns
	// ErrNotFound if the master is absent.
	AddVLESSClientToDevice(ctx context.Context, masterID string, c domain.VLESSClient, deviceID string, createdAt time.Time) error

	// FindUnattachedWGClient is the legacy portal lookup: it finds a WG credential
	// by ID alone, across every master, but only when it has never belonged to a
	// device (device_id IS NULL and its personal link was never retired). Returns
	// ErrNotFound otherwise.
	FindUnattachedWGClient(ctx context.Context, id string) (string, domain.WGClient, error)

	// AdoptWGCredentialsAsDevices wraps every AWG credential without a device into
	// a device of its own (token = credential ID), once per database; later calls
	// return 0. at stamps the marker — the caller reads the clock.
	AdoptWGCredentialsAsDevices(ctx context.Context, at time.Time) (int, error)

	// RecordStatus stores the latest status report for a node, overwriting any
	// previous report, and stamps the node's LastSeen.
	RecordStatus(ctx context.Context, s domain.NodeStatus) error

	// GetStatus returns the latest status for a node, or ErrNotFound.
	GetStatus(ctx context.Context, id string) (domain.NodeStatus, error)
	// GetAWGPortRotation returns the generation of an exit-initiated tunnel's
	// pinned master port and when it last moved; 0 and zero time when it never has.
	GetAWGPortRotation(ctx context.Context, master, exit string) (int, time.Time, error)
	// SetAWGPortRotation records a move to generation gen at time at.
	SetAWGPortRotation(ctx context.Context, master, exit string, gen int, at time.Time) error
	// AdoptAWGPortRotation gives the generations recorded before tunnels were keyed
	// by master to master — the one master there was — and reports how many it
	// moved. One-shot: it runs once per database, whoever is passed later.
	AdoptAWGPortRotation(ctx context.Context, master string) (int, error)

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
