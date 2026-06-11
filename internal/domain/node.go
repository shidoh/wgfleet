package domain

import "time"

// SSHTarget describes how to reach a blank VM during the provisioning
// bootstrap. It is used ONLY in Phase 0/1; once the agent is installed the
// controller talks to the node over mTLS and SSH management is no longer used.
type SSHTarget struct {
	Host    string // public IP or hostname reachable for bootstrap
	Port    int    // SSH port, defaults to 22 when zero
	User    string // bootstrap user (must allow pubkey auth)
	KeyPath string // path to the private key used for bootstrap, never stored in git
	// HostKey, when set, pins the server's SSH host key (an authorized_keys /
	// known_hosts public-key line, e.g. "ssh-ed25519 AAAA..."). Bootstrap uploads
	// the node's mTLS private key over this channel, so an unverified host key lets
	// a MITM steal the node's control-plane identity — pin it whenever the key is
	// known. Empty falls back to trust-on-first-use with a logged warning.
	HostKey string
}

// Addr returns "host:port", substituting the default SSH port when unset.
func (t SSHTarget) Addr() string {
	port := t.Port
	if port == 0 {
		port = 22
	}
	return joinHostPort(t.Host, port)
}

// Node is one managed machine in the fleet. It is observed/inventory state:
// what the controller knows about the box, as opposed to NodeSpec which is the
// desired state the agent drives toward.
type Node struct {
	ID       string // stable, controller-assigned identifier
	Name     string // human-friendly, e.g. "exit-de-1"
	Role     Role
	Region   string    // free-form: "de", "nl", "fi"...
	MgmtAddr string    // address controller/agent talk over (ZT overlay)
	PublicIP string    // discovered; used as the endpoint for WG peers
	SSH      SSHTarget // bootstrap only
	State    NodeState

	// PublicKey is the node's WireGuard public key. The matching private key
	// is generated and kept ON the node and never leaves it; the controller
	// only ever sees this pubkey (key-broker model).
	PublicKey string

	// Drain, when set, takes the node out of the load balancer: it stays a
	// configured peer/proxy (existing connections survive) but receives no new
	// traffic. The operator drains, then deletes. Independent of State (health).
	Drain bool

	// Decommission, when set, tells the agent to tear down the node's data plane
	// (stop containers/services, bring down tunnels, clear routing/firewall) — the
	// reverse of reconcile. The operator drains, decommissions, then deletes.
	Decommission bool

	CreatedAt time.Time
	UpdatedAt time.Time
	LastSeen  time.Time // last status report received from the agent
	LastError string    // most recent reconcile/provision error, if any
}

// NodeStatus is a point-in-time health report pushed by an agent. It is the
// agent's view of reality, reconciled against the Node's desired NodeSpec.
type NodeStatus struct {
	NodeID         string
	State          NodeState
	ReportedAt     time.Time
	LastHandshake  time.Time     // freshest WG handshake across peers
	EgressIP       string        // observed egress IP (should be Cloudflare for warp)
	ReconcileError string        // non-empty if the last reconcile failed
	Checks         []HealthCheck // individual self-check results
}

// HealthCheck is a single named self-check result from an agent.
type HealthCheck struct {
	Name    string
	OK      bool
	Detail  string
	Latency time.Duration
}
