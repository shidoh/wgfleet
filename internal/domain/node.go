package domain

import (
	"fmt"
	"time"
)

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
	Region   string // free-form: "de", "nl", "fi"...
	MgmtAddr string // address controller/agent talk over (ZT overlay)
	// PublicIP is a COPY of the manifest's public_ip, taken at provisioning time.
	// Nothing discovers it (the agent advertises one only under --public-ip, which
	// no installed unit passes), so it is not a live fact about the node: the
	// manifest is what peers and clients are dialled at, and this is only the
	// fallback for a node the manifest declares no address for. See
	// keybroker.masterEndpointHost.
	PublicIP string
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

	// ClientVLESSPublicKey is the master's CLIENT-FACING REALITY x25519 public key
	// (the client VLESS inbound), published separately from RealityPublicKey — a
	// co-located controller+master carries both. It seeds the vless:// links the UI
	// hands end users. Like the others, the private key never leaves the master.
	ClientVLESSPublicKey string
	// ClientWGPublicKey is the master's CLIENT-FACING WireGuard public key: the
	// identity of the interface end users dial, published by the agent so the
	// controller can render client configs. Empty while wg-easy owns that leg.
	ClientWGPublicKey string
	// LifelinePublicKey is the exit's LIFELINE WireGuard public key: the identity
	// of LifelineInterface ("awgl0"), the reserve client-facing interface an exit
	// may carry (NodeSpec.Lifeline). Published separately from PublicKey (the
	// master↔exit tunnel identity) and from ClientWGPublicKey (the master's own
	// client leg) because all three are distinct interfaces that can coexist on
	// the same node. Like the others, the private key never leaves the node.
	// Empty when the exit carries no lifeline.
	LifelinePublicKey string

	// Drain, when set, takes the node out of the load balancer: it stays a
	// configured peer/proxy (existing connections survive) but receives no new
	// traffic. The operator drains, then deletes. Independent of State (health).
	Drain bool
	// DrainByConfig reports that the manifest declares this exit drained
	// (fleet.exits[].drain). Not persisted: it is read from the manifest each time
	// and shown so the console can say WHY the node is out of routing and refuse
	// to undrain what the file will drain again.
	DrainByConfig bool

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
	LastHandshake  time.Time          // freshest WG handshake across peers
	EgressIP       string             // observed egress IP (should be Cloudflare for warp)
	ReconcileError string             // non-empty if the last reconcile failed
	Checks         []HealthCheck      // individual self-check results
	ExitHealth     []ExitTunnelHealth // master only: per-exit tunnel health from mihomo
	// ClientPeers is the master's view of the end users on its client-facing
	// interface, read from the live interface rather than from desired state. It
	// only appears once the agent owns that interface; while wg-easy holds it, the
	// same numbers come from wg-easy's own metrics endpoint.
	ClientPeers []ClientPeerStatus
	// AWGMasterEndpoint is the endpoint an exit's awg0 currently holds for the
	// master peer given one (exit-initiated AWG flow). Empty when none has one.
	AWGMasterEndpoint string
}

// ClientPeerStatus is one end user's live peer on the master's client interface.
// Keyed by public key rather than by name: the interface knows nothing about
// labels, and the controller matches these back onto its credentials.
// It deliberately does NOT carry the peer's endpoint. That is the end user's
// real, pre-tunnel IP — the single piece of data this system exists to keep
// nobody from having. Reporting it would persist a connection log in the
// controller's store, put it in every backup, and (under ADR-0027) replicate it
// to every master, in exchange for a column no page displays.
type ClientPeerStatus struct {
	PublicKey     string
	LastHandshake time.Time // zero when the peer has never completed one
	ReceivedBytes int64
	SentBytes     int64
}

// HealthCheck is a single named self-check result from an agent.
type HealthCheck struct {
	Name    string
	OK      bool
	Detail  string
	Latency time.Duration
}

// ExitTunnelHealth is the master's view of one master↔exit tunnel, derived from
// mihomo's Clash API (the tunnels are userspace mihomo proxies, not kernel WG, so
// this — not a wg handshake — is their liveness). One per exit on a master node.
type ExitTunnelHealth struct {
	Name     string        // exit node name (== mihomo proxy name)
	Alive    bool          // mihomo reports the proxy up
	Delay    time.Duration // last url-test delay (0 = no/failed measurement)
	LastTest time.Time     // time of the last delay test (zero = none)
	// Selected reports that this exit currently carries traffic. Under a
	// single-carrier group kind (url-test, fallback) exactly one exit is selected;
	// under load-balance every live member of the active tier is (ADR-0029).
	Selected bool
	// HeldOut is the MASTER'S OWN verdict: its multi-destination probe judged this
	// tunnel unusable and pulled it out of the load balancer. Distinct from Alive
	// above, which is mihomo's single-URL check — the two write the same flag under
	// different criteria, and only this one knows WHY an exit left the rotation.
	//
	// It is reported only for the tier that carries traffic. An idle reserve member
	// is in no group, so "held out" would be a claim about a rotation it is not in.
	HeldOut bool
	// Reachable/Probed are the probe result behind the verdict. Probed == 0 means
	// this exit was not sampled on the last pass (the scan stops at the first usable
	// member), which is absent evidence rather than evidence of health.
	Reachable int
	Probed    int
	// HeldSince is when the current hold began — not when it was last re-confirmed,
	// so "held out 12 minutes" stays true as the spell runs. Zero when not held.
	HeldSince time.Time
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

// AuthRecord is the single web-panel admin credential (one row). PasswordHash is
// a bcrypt hash; SessionSecret is the HMAC key used to sign session cookies —
// rotating it invalidates every issued session. It never leaves the controller.
type AuthRecord struct {
	Username      string
	PasswordHash  string
	SessionSecret []byte
	UpdatedAt     time.Time
}

// AgentBackReason reports why this node does not yet count as "back after an agent
// upgrade", or "" when it does.
//
// All four conditions are load-bearing and none is sufficient alone: Ready can be
// stale state left behind by the previous binary, a matching version does not mean
// the reconcile is healthy, a LastSeen from before the restart belongs to the old
// process, and a report that is merely recent enough can still be minutes old on a
// node that has since wedged.
//
// It lives here rather than in the rollout coordinator because three other things
// upgrade an agent — the CLI's --upgrade-agent, the Web UI button and the
// wire-version gate's automatic push — and all three used to upload, restart and
// report success without ever asking whether the node came back. The coordinator
// was the only caller that checked, and a check only one of four callers performs
// is a check the operator cannot rely on.
func (n Node) AgentBackReason(want string, restartedAt, now time.Time, freshWithin time.Duration) string {
	return n.AgentBackReasonFrom(StateReady, want, restartedAt, now, freshWithin)
}

// AgentBackReasonFrom is AgentBackReason with the bar set by where the node stood
// BEFORE the upgrade: a node that was Degraded going in has come back when it is
// Degraded again, not only when it is Ready.
//
// Demanding Ready of every node made a degraded node un-upgradeable: anz3 sat
// Degraded on a throttled WARP path for a day, every rollout halted at it — rolled
// it back, skipped the four nodes behind it — and the exit whose throughput check
// was failing was, by construction, the one that could never receive a fix. The
// gate exists to catch a binary that broke a node; a node that arrives broken and
// leaves exactly as broken has not been broken by the binary. Error never passes:
// it is not a degree of health, it is the reconcile failing.
func (n Node) AgentBackReasonFrom(before NodeState, want string, restartedAt, now time.Time, freshWithin time.Duration) string {
	switch {
	case n.State == StateReady:
	case n.State == StateDegraded && before == StateDegraded:
	default:
		return "state is " + string(n.State)
	}
	if n.AgentVersion != want {
		return fmt.Sprintf("reports version %q, want %q", n.AgentVersion, want)
	}
	if !n.LastSeen.After(restartedAt) {
		return "has not reported since the restart"
	}
	if age := now.Sub(n.LastSeen); age > freshWithin {
		return fmt.Sprintf("last report is %s old", age.Truncate(time.Second))
	}
	return ""
}
