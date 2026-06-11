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

	// DeleteNode removes a node and its status. Returns ErrNotFound if absent.
	DeleteNode(ctx context.Context, id string) error

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

	// RecordStatus stores the latest status report for a node, overwriting any
	// previous report, and stamps the node's LastSeen.
	RecordStatus(ctx context.Context, s domain.NodeStatus) error

	// GetStatus returns the latest status for a node, or ErrNotFound.
	GetStatus(ctx context.Context, id string) (domain.NodeStatus, error)

	// Close releases the underlying database handle.
	Close() error
}
