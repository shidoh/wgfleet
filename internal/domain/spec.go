package domain

import (
	"errors"
	"fmt"
)

// DefaultKeepaliveSeconds is the persistent-keepalive applied to peers behind
// NAT when a spec leaves it unset.
const DefaultKeepaliveSeconds = 25

// NodeSpec is the DESIRED state of one node — the target the agent's reconcile
// loop converges toward, idempotently and with dry-run support. It is rendered
// by the controller from inventory + fleet config and pulled by the agent.
type NodeSpec struct {
	Role   Role
	Egress EgressMethod // exit nodes only: the PREFERRED egress (== EgressChain[0])
	// EgressChain is the ordered egress priority list for censorship-adaptive
	// failover (ADR-0017): index 0 is preferred (== Egress), later entries are
	// fallbacks the agent switches to when the active one is blocked (ADR-0016).
	// Empty ⇒ no failover (treated as [Egress]). The agent selects the active
	// method within this chain; the controller only sets the intent.
	EgressChain []EgressMethod
	WGServer    WGServerSpec
	Peers       []PeerSpec // rendered by the controller from registered pubkeys
	DNS         DNSFilterSpec
	Firewall    FirewallSpec
	Routing     RoutingSpec
	Exporters   ExportersSpec
	Master      *MasterSpec // master nodes only: mihomo data plane; nil for exits
	// WARPMTU is the MTU for the exit's WARP egress interface (warp egress only).
	// 0 means compute it from the sequential model (1440); set it when the real
	// WARP→Cloudflare path MTU is smaller than the physical link (an earlier finding: the
	// observed band is 1320-1420 depending on the channel). The controller also
	// folds the smallest exit WARP MTU into the client-facing MTU so client
	// packets never fragment at egress.
	WARPMTU int
	// EgressThroughputMinBps is the egress throughput floor in bytes/sec below which
	// the exit's active egress is considered throughput-degraded (a slow/throttled
	// path that small-packet health checks — and mihomo's latency-only url-test —
	// cannot see). 0 disables the throughput watchdog. When degraded, the agent
	// fails over to a fallback egress if one exists (ADR-0017) and the controller
	// auto-suspends the exit from the master LB group (ADR-0021).
	EgressThroughputMinBps int
	// EgressThroughputProbeURL is the URL the throughput watchdog downloads through
	// the active egress interface to measure bytes/sec. Empty ⇒ the agent default.
	EgressThroughputProbeURL string
	// EnabledTransports lists the master↔exit transports this exit runs (exit only,
	// ADR-0025). Empty ⇒ [TransportAWG] (back-compat: AWG-only). The exit keeps every
	// enabled transport's server warm; the master places only the active one in its
	// load-balance group.
	EnabledTransports []MasterTransport
	// ActiveTransport is the transport currently routed to (placed in the master LB
	// group). Informational on the exit side — the master enforces it via LB
	// membership — but carried here so the exit can report/observe it. Empty ⇒
	// TransportAWG.
	ActiveTransport MasterTransport
	// Reality is the VLESS+REALITY+XHTTP inbound server spec (exit only), set when
	// TransportRealityXHTTP is enabled. nil otherwise.
	Reality *RealityServerSpec
	// Hardening is the host-hardening policy: which of the managed hardening
	// subsystems (sshd drop-in, fail2ban jail) the agent reconciles. nil ⇒ not
	// configured, which every reader treats as BOTH ENABLED — the fail-safe default
	// and the pre-wire-v6 behaviour, so a bare NodeSpec{} (tests, a cached spec from
	// an older controller) never leaves a node un-hardened. Read it through
	// SSHDHardeningEnabled/Fail2banEnabled, never directly.
	Hardening *HardeningSpec
	// Decommission tells the agent to tear the node down (reverse reconcile)
	// instead of converging it. Rendered when the node is flagged for removal.
	Decommission bool
}

// HardeningSpec is the operator's host-hardening policy for one node. It exists as
// a separate, pointer-held struct precisely so "unset" is distinguishable from
// "both off": the default must be ON, and a plain pair of bools on NodeSpec would
// make the zero value mean "disable everything".
type HardeningSpec struct {
	// SSHD enables the managed sshd drop-in (key-only auth, no root password, no
	// X11 forwarding), continuously reconciled.
	SSHD bool
	// Fail2ban enables the managed fail2ban sshd jail, continuously reconciled.
	Fail2ban bool
}

// SSHDHardeningEnabled reports whether the agent should manage the sshd drop-in.
// An unset policy means enabled (see NodeSpec.Hardening).
func (s NodeSpec) SSHDHardeningEnabled() bool {
	return s.Hardening == nil || s.Hardening.SSHD
}

// Fail2banEnabled reports whether the agent should manage the fail2ban sshd jail.
// An unset policy means enabled (see NodeSpec.Hardening).
func (s NodeSpec) Fail2banEnabled() bool {
	return s.Hardening == nil || s.Hardening.Fail2ban
}

// Transports returns the exit's enabled master↔exit transports, falling back to a
// single-entry [TransportAWG] when none is set (an AWG-only exit, pre-ADR-0025).
func (s NodeSpec) Transports() []MasterTransport {
	if len(s.EnabledTransports) > 0 {
		return s.EnabledTransports
	}
	return []MasterTransport{TransportAWG}
}

// HasTransport reports whether the exit runs transport t.
func (s NodeSpec) HasTransport(t MasterTransport) bool {
	for _, e := range s.Transports() {
		if e.OrDefault() == t.OrDefault() {
			return true
		}
	}
	return false
}

// EgressMethods returns the egress priority chain, falling back to a single-entry
// [Egress] chain when none is set (a node with no configured failover).
func (s NodeSpec) EgressMethods() []EgressMethod {
	if len(s.EgressChain) > 0 {
		return s.EgressChain
	}
	if s.Egress == "" {
		return nil
	}
	return []EgressMethod{s.Egress}
}

// EgressChainHas reports whether m is a candidate egress for this node. The exit
// WARP planner uses it to keep wgcf up while WARP is anywhere in the chain (so a
// failed-over node can still probe WARP for recovery), not only when it is active.
func (s NodeSpec) EgressChainHas(m EgressMethod) bool {
	for _, c := range s.EgressMethods() {
		if c == m {
			return true
		}
	}
	return false
}

// CheckEgressActive is the conventional name of the self-check the exit agent
// emits to report which egress method is currently active (its Detail is the
// method). It rides the health-check channel so the active egress reaches the UI
// and metrics without a NodeStatus schema change (ADR-0017).
const CheckEgressActive = "egress-active"

// CheckEgressThroughput is the conventional name of the self-check the exit agent
// emits to report whether its active egress meets the throughput floor (ADR-0021).
// Its OK field is false only once throughput is SUSTAINED-degraded (the watchdog's
// hysteresis has tripped), so the controller can read this single boolean to
// auto-suspend the exit from the LB group without re-deriving the streak. Detail
// carries the last measured rate. Absent when the watchdog is disabled.
const CheckEgressThroughput = "egress-throughput"

// WGServerSpec is the local AmneziaWG listener this node runs. All fleet-internal
// tunnels (client↔master, master↔exit) are AmneziaWG, so AWG is populated for
// them; it is nil only for the external WARP/wgcf leg, which speaks vanilla
// WireGuard because it terminates on Cloudflare. AmneziaWG obfuscation lives in
// the [Interface] section only — hence on the server spec, never on peers.
type WGServerSpec struct {
	ListenPort  int        // UDP; prefer standard ports (443/51820), see an earlier finding
	AddressPool string     // CIDR the server hands out, e.g. "10.81.0.0/24"
	Address     string     // this server's own address inside the pool
	MTU         int        // computed along the tunnel chain, never guessed
	AWG         *AWGParams // AmneziaWG obfuscation for this interface (server end); nil ⇒ vanilla WG
	// ClientAWGLocal is the per-end decoy (Jc/Jmin/Jmax, I1-I5) the CLIENT side of
	// this tunnel must emit. AWG permits these to differ per end, so where they may
	// differ they MUST: clients get their own junk profile, distinct from the
	// server interface's AWG.Local. The shared S1-S4/H1-H4 still come from AWG
	// (clients derive them from the interface). nil ⇒ fall back to AWG.Local.
	ClientAWGLocal *AWGLocal
}

// PeerSpec is one AmneziaWG peer as seen from a node. Peers carry no obfuscation
// parameters — those are interface-wide (WGServerSpec.AWG). Endpoint is empty
// when this node is the server side of the relationship.
type PeerSpec struct {
	Name       string
	PublicKey  string
	Endpoint   string // host:port; empty if the peer dials us
	AllowedIPs []string
	Keepalive  int // seconds; 0 means use DefaultKeepaliveSeconds when behind NAT
	MTU        int // computed per the tunnel chain
}

// DNSFilterSpec configures the on-node filtering resolver. On MVP this is blocky
// run as a Docker container (ADR-0013). Only safety/structural fields are
// first-class: the binds are pinned to loopback + the mgmt/ZT address so the
// resolver is never reachable on the public interface (docs/DESIGN.md §9), plus
// upstreams/bootstrap with safe defaults and a self-protection allowlist. The
// richer blocky surface (denylists, conditional split-horizon mappings, caching
// tuning, extra upstream groups) is operator-driven through Custom (deep-merged
// overrides + extra include files), mirroring the mihomo renderer — we render a
// base from desired state, not a fork per option (docs/DESIGN.md principle 7).
type DNSFilterSpec struct {
	Enabled  bool
	MgmtAddr string // ZT/mgmt address — a non-loopback address blocky binds
	// ClientBindAddr is an ADDITIONAL non-loopback bind for the master-tier resolver
	// (ADR-0024): the client-pool gateway (e.g. "10.73.0.1"), so VPN clients can use
	// the master as their DNS through the tunnel. It is tunnel-internal, reachable
	// only from inside the authenticated AWG tunnel — never the public interface.
	// Agent-populated on the master from MasterSpec.BindAddress (like
	// RoutingSpec.ClientCIDR, it needs no wire field); empty on exits.
	ClientBindAddr string
	Ports          DNSPorts
	// Upstreams is the default upstream group (DoT/DoH/plain). Safe defaults are
	// used when empty.
	Upstreams []string
	// BootstrapDNS resolves the hostnames of DoT/DoH upstreams before the
	// resolver itself is up. Safe defaults are used when empty.
	BootstrapDNS []BootstrapUpstream
	// Allowlist holds operator domains that must never be blocked. Platform
	// control-plane domains (ZeroTier, AmneziaWG) are always merged in so the
	// fleet cannot filter its own infrastructure.
	Allowlist  []string
	Prometheus bool         // expose blocky's Prometheus /metrics
	Image      string       // container image; defaults to spx01/blocky
	Custom     CustomConfig // deep-merged overrides + extra include files
}

// DNSPorts are the per-protocol listen ports for the resolver. Each is bound on
// loopback and the mgmt/ZT address only (never the public interface). A zero
// value disables that protocol; DNS defaults to 53 when zero.
type DNSPorts struct {
	DNS   int // plain DNS, default 53
	TLS   int // DNS-over-TLS, default 853 (0 disables)
	HTTPS int // DNS-over-HTTPS, default 0 (needs a cert; disabled)
	HTTP  int // HTTP API/metrics, default 4000 (0 disables)
}

// BootstrapUpstream is one bootstrap resolver: an upstream plus the IPs used to
// reach it (so its own hostname need not be resolved first).
type BootstrapUpstream struct {
	Upstream string
	IPs      []string
}

// FirewallSpec is the nftables policy intent for a node.
type FirewallSpec struct {
	ASBlacklist bool     // drop scanning ASNs via an nftables set
	Whitelist   []string // always-allow sources (mgmt overlay, master IP, ...)
	WGPort      int      // UDP port to open for the WG listener
	// RealityPort is the TCP port the REALITY/XHTTP inbound (xray) listens on
	// (ADR-0025). Unlike the AWG WGPort (UDP), this is TCP. 0 ⇒ not opened (the exit
	// does not run the reality transport).
	RealityPort int
	// PublicTCPPorts are TCP ports opened to the WORLD (no interface scope), for
	// services that must be reachable from the public internet — e.g. the decoy web
	// listener on 80/443. Role-agnostic: it applies to masters and exits alike.
	//
	// Distinct from MasterSpec.ClientAdminPorts, which is scoped to the client WG
	// interface and exposes admin UIs to the client pool only. Opening a port here
	// exposes it to every source the drop policy would otherwise block, so keep the
	// list to services that are genuinely meant to be public.
	//
	// The renderer normalises the list (drops out-of-range entries, dedupes, sorts)
	// so the rendered ruleset is byte-stable across passes regardless of manifest
	// order — an unstable render would re-apply the firewall on every reconcile.
	PublicTCPPorts []int

	// PublicUDPPorts are UDP ports opened to the WORLD (no interface scope) — the
	// UDP sibling of PublicTCPPorts. Its motivating case is a second ZeroTier node
	// (a network controller) running alongside the node's own member instance,
	// which must use a non-default port because the member already holds 9993.
	// Role-agnostic: it applies to masters and exits alike.
	//
	// Opening a port here exposes it to every source the drop policy would
	// otherwise block, so keep the list to services genuinely meant to be public.
	//
	// The renderer normalises the list (drops out-of-range entries, dedupes, sorts)
	// so the rendered ruleset is byte-stable across passes regardless of manifest
	// order — an unstable render would re-apply the firewall on every reconcile.
	PublicUDPPorts []int
}

// RoutingSpec captures policy-routing intent, translated to ip rule/route by
// the routing reconciler. The fields encode the hard-won rules from earlier findings
// : WARP must not capture management/handshake traffic.
type RoutingSpec struct {
	// EgressInterface is the interface client traffic should leave through
	// (e.g. the wgcf/WARP interface on an exit node).
	EgressInterface string
	// DirectCIDRs always route via the main table, never through egress
	// (RU/private destinations, the master's IP, ZeroTier, own networks).
	DirectCIDRs []string
	// MasterIP is the master endpoint; replies to it must go direct.
	MasterIP string
	// FwMark marks WG-handshake/reply packets so source routing keeps them
	// direct instead of sending them into WARP.
	FwMark int
	// ClientCIDR is the SOURCE subnet whose traffic is sent to the egress table.
	// The egress ip-rule MUST be scoped `from <ClientCIDR>` — never `from all`, or
	// the node's OWN host traffic (SSH, DNS, package/image pulls, the wgcf handshake
	// itself) is pulled into WARP and the box is cut off when WARP is down (earlier findings
	// ). It is the exit's WG pool, populated agent-side from WGServer.AddressPool
	// (so it needs no wire field); empty ⇒ no egress rule is rendered (fail-safe).
	ClientCIDR string
	// RealityEgressMark is the SO_MARK the xray REALITY inbound stamps on its
	// outbound sockets (ADR-0025). xray dials FROM THE HOST, so the `from
	// <ClientCIDR>` egress rule does not catch its connections; a dedicated `fwmark
	// <mark> lookup <egress-table>` rule sends them through WARP instead. Populated
	// agent-side (a fixed constant) when the exit runs the reality transport with a
	// WARP egress; 0 ⇒ no such rule (direct egress, or no reality transport).
	RealityEgressMark int
}

// ExportersSpec selects which Prometheus endpoints the agent runs. Host metrics
// are delegated to node_exporter rather than duplicated.
type ExportersSpec struct {
	Node bool // run/scrape node_exporter
	WG   bool // export WG handshake age, rx/tx, peer count
	WARP bool // export wgcf tunnel status + egress self-check
}

// Validate checks a NodeSpec for the invariants the platform must hold before
// it is ever applied to a node. It returns a joined error describing every
// violation rather than failing on the first.
func (s NodeSpec) Validate() error {
	// A decommission spec drives teardown, not convergence, so the normal
	// reconcile invariants (valid WG server, peers, ...) do not apply.
	if s.Decommission {
		if !s.Role.Valid() {
			return fmt.Errorf("invalid role %q", s.Role)
		}
		return nil
	}
	var errs []error
	if !s.Role.Valid() {
		errs = append(errs, fmt.Errorf("invalid role %q", s.Role))
	}
	if s.Role == RoleExit && !s.Egress.Valid() {
		errs = append(errs, fmt.Errorf("exit node has invalid egress %q", s.Egress))
	}
	for i, m := range s.EgressChain {
		if !m.Valid() {
			errs = append(errs, fmt.Errorf("egress chain[%d] has invalid/unimplemented method %q", i, m))
		}
	}
	if len(s.EgressChain) > 0 && s.EgressChain[0] != s.Egress {
		errs = append(errs, fmt.Errorf("egress chain[0] %q must equal the preferred egress %q", s.EgressChain[0], s.Egress))
	}
	// Transport set (ADR-0025): every enabled transport must be known, the active
	// one must be enabled, and TransportRealityXHTTP requires a Reality server spec.
	for i, t := range s.EnabledTransports {
		if !t.Valid() {
			errs = append(errs, fmt.Errorf("enabled transport[%d] %q is unknown", i, t))
		}
	}
	if s.ActiveTransport != "" {
		if !s.ActiveTransport.Valid() {
			errs = append(errs, fmt.Errorf("active transport %q is unknown", s.ActiveTransport))
		} else if !s.HasTransport(s.ActiveTransport) {
			errs = append(errs, fmt.Errorf("active transport %q is not in the enabled set", s.ActiveTransport))
		}
	}
	if s.HasTransport(TransportRealityXHTTP) && s.Reality == nil {
		errs = append(errs, errors.New("reality-xhttp transport enabled but Reality server spec is missing"))
	}
	// ClientWG is DELIBERATELY not validated here. The agent refuses the whole spec
	// when this returns an error, so folding the client interface in gave one bad
	// credential — or a pool narrowed in the manifest below an address already
	// issued — the power to stop the master converging ANYTHING: mihomo, the master
	// NAT, DOCKER-USER, blocky and the VLESS inbound with it. clientWGPlanner
	// already validates it and defers just that one component, keeping the
	// last-good interface config serving; that soft-fail is the intended behaviour
	// and it could never run while this gate stood in front of it.
	// ClientVLESS is not validated here either, for the reason stated just above it.
	// It used to be, in the very next statement after that paragraph: a bad SNI or an
	// unusable camouflage target failed the whole spec, the agent refused it, and the
	// master stopped converging mihomo, the NAT, DOCKER-USER, blocky and the client
	// interface — a client transport nobody may even be using taking the data plane
	// down with it. clientVlessPlanner validates it and defers that one component,
	// which is what the paragraph above argues for and what this line prevented.
	if s.WGServer.ListenPort <= 0 || s.WGServer.ListenPort > 65535 {
		errs = append(errs, fmt.Errorf("WG listen port %d out of range", s.WGServer.ListenPort))
	}
	if s.WGServer.AddressPool == "" {
		errs = append(errs, errors.New("WG server address pool is required"))
	}
	if s.WGServer.MTU != 0 && (s.WGServer.MTU < 1280 || s.WGServer.MTU > 1500) {
		// 1280 is the IPv6 minimum MTU; below it tunnels are unreliable.
		errs = append(errs, fmt.Errorf("WG server MTU %d outside sane range [1280,1500]", s.WGServer.MTU))
	}
	if s.WGServer.AWG != nil {
		if err := s.WGServer.AWG.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("wg server AWG: %w", err))
		}
	}
	for i, p := range s.Peers {
		if p.PublicKey == "" {
			errs = append(errs, fmt.Errorf("peer %d (%s): missing public key", i, p.Name))
		}
		if len(p.AllowedIPs) == 0 {
			errs = append(errs, fmt.Errorf("peer %d (%s): no allowed IPs", i, p.Name))
		}
	}
	return errors.Join(errs...)
}
