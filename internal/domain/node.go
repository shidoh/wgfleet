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
	// InsecureIgnoreHostKey disables host-key verification entirely for this
	// target (even when HostKey is set). It is an explicit, logged escape hatch
	// for trusted networks / first-run bring-up where pinning is impractical —
	// the same effect as an empty HostKey but stated intentionally. Prefer pinning
	// HostKey; this trades away MITM protection on the bootstrap channel.
	InsecureIgnoreHostKey bool
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

	// RealityPublicKey is the exit's REALITY x25519 public key (ADR-0025),
	// published separately from PublicKey and only set on exits that run the
	// reality transport. Like PublicKey, the private key never leaves the node.
	RealityPublicKey string

	// Drain, when set, takes the node out of the load balancer: it stays a
	// configured peer/proxy (existing connections survive) but receives no new
	// traffic. The operator drains, then deletes. Independent of State (health).
	Drain bool

	// Decommission, when set, tells the agent to tear down the node's data plane
	// (stop containers/services, bring down tunnels, clear routing/firewall) — the
	// reverse of reconcile. The operator drains, decommissions, then deletes.
	Decommission bool

	// ActiveTransport, when set, overrides the manifest's active master↔exit
	// transport for this exit (ADR-0025): it is the operator's live UI choice of
	// which transport (awg | reality-xhttp) the master routes to. Empty ⇒ use the
	// manifest's active_transport. The keybroker honors it only if it is one of the
	// exit's enabled transports.
	ActiveTransport MasterTransport

	// AgentVersion is the build identity (version.Short()) the agent last reported
	// over gRPC metadata; WireVersion is its protocol version. Both are observed,
	// not desired — the controller records them to surface version skew in the UI
	// and metrics and to gate incompatible agents. Empty/0 until first contact.
	AgentVersion string
	WireVersion  uint32

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

// EgressReachability classifies WHY an exit's egress is or is not working, so an
// operator can tell a path/ISP block (the censorship signature) from a transient
// downstream failure. It is observational only — the node's lifecycle State still
// goes Degraded on a failed egress check; this adds the reason. It is the
// detect-only foundation for censorship-adaptive transport failover (the agent
// does not yet switch transport on it).
type EgressReachability string

const (
	// EgressReachOK — egress confirmed leaving via WARP.
	EgressReachOK EgressReachability = "ok"
	// EgressReachDegraded — egress failing but the WARP tunnel is still reachable
	// (a transient Cloudflare blip or a downstream issue, not a path block).
	EgressReachDegraded EgressReachability = "degraded"
	// EgressReachBlocked — egress failing AND the WARP path itself is unreachable
	// (WG control packets to the Cloudflare endpoint are not getting through):
	// the signature of an ISP/DPI block.
	EgressReachBlocked EgressReachability = "blocked"
)

// CheckEgressReachability is the conventional name of the self-check the exit
// agent emits to carry the egress classification across the wire. Its OK field is
// false only when egress is classified blocked, so the UI/metrics can flag a
// censorship block without parsing the detail string.
const CheckEgressReachability = "egress-reachability"

// CheckSpecValid is the conventional name of the self-check the agent emits when
// it refuses to apply an invalid desired spec. Its OK field is false with the
// validation error as the detail, so the controller/UI surface why the node is in
// Error rather than silently applying a broken config.
const CheckSpecValid = "spec-valid"

// EgressBlocked reports whether the agent classified this node's egress as
// path/ISP-blocked — the censorship-block signal behind the UI badge and metric.
func (s NodeStatus) EgressBlocked() bool {
	for _, c := range s.Checks {
		if c.Name == CheckEgressReachability {
			return !c.OK
		}
	}
	return false
}

// EgressThroughputDegraded reports whether the agent classified this node's active
// egress as throughput-degraded (the egress-throughput self-check is present and
// failing, ADR-0021). The keybroker reads this to auto-suspend the exit from the
// master LB group. False when the check is absent (watchdog disabled / not yet
// reported), so a node never auto-suspends on missing data.
func (s NodeStatus) EgressThroughputDegraded() bool {
	for _, c := range s.Checks {
		if c.Name == CheckEgressThroughput {
			return !c.OK
		}
	}
	return false
}

// ActiveEgress returns the egress method the agent currently has active (from the
// egress-active self-check, ADR-0017), or "" when not reported. It differs from
// the preferred egress while the node is failed over.
func (s NodeStatus) ActiveEgress() string {
	for _, c := range s.Checks {
		if c.Name == CheckEgressActive {
			return c.Detail
		}
	}
	return ""
}
