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
	Role      Role
	Egress    EgressMethod // exit nodes only
	WGServer  WGServerSpec
	Peers     []PeerSpec // rendered by the controller from registered pubkeys
	DNS       DNSFilterSpec
	Firewall  FirewallSpec
	Routing   RoutingSpec
	Exporters ExportersSpec
	Master    *MasterSpec // master nodes only: mihomo data plane; nil for exits
	// WARPMTU is the MTU for the exit's WARP egress interface (warp egress only).
	// 0 means compute it from the sequential model (1440); set it when the real
	// WARP→Cloudflare path MTU is smaller than the physical link (an earlier finding: the
	// observed band is 1320-1420 depending on the channel). The controller also
	// folds the smallest exit WARP MTU into the client-facing MTU so client
	// packets never fragment at egress.
	WARPMTU int
	// Decommission tells the agent to tear the node down (reverse reconcile)
	// instead of converging it. Rendered when the node is flagged for removal.
	Decommission bool
}

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
	AWG         *AWGParams // AmneziaWG obfuscation for this interface; nil ⇒ vanilla WG
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
	MgmtAddr string // ZT/mgmt address — the ONLY non-loopback address blocky binds
	Ports    DNSPorts
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
