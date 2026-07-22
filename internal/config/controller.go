package config

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/routing"
	"github.com/shidoh/wgfleet/internal/wg"
)

// zerotierNetworkID matches a ZeroTier network id: exactly 16 hexadecimal digits.
var zerotierNetworkID = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// ExpandPath expands a leading ~ or ~/ in a filesystem path to the user's home
// directory. Config values are read directly with os.ReadFile, which does not
// understand the shell ~ convention, so an operator-written "~/.ssh/id_ed25519"
// would otherwise fail with "no such file or directory". Non-tilde paths and
// "~user" forms are returned unchanged.
func ExpandPath(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// os.UserHomeDir reads $HOME, which systemd often leaves UNSET for services
		// (notably root services with no User=), so it fails there. Fall back to the
		// passwd database via os/user, which still yields e.g. /root — without this the
		// controller's "~/.ssh/id_ed25519" key path stays literally "~/…" and every SSH
		// dial (provision AND the UI/auto agent upgrade) fails "no such file or
		// directory". Only give up (return p) if even the passwd lookup has no home.
		u, uerr := user.Current()
		if uerr != nil || u.HomeDir == "" {
			return p
		}
		home = u.HomeDir
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

// ControllerConfig is the top-level config for a wgfleet-controller process,
// loaded from controller.yaml. It is config-driven by design: CLI flags only
// override these values.
type ControllerConfig struct {
	Controller ControllerSection `koanf:"controller"`
	Fleet      FleetSection      `koanf:"fleet"`
}

// ControllerSection holds the controller's own runtime settings.
type ControllerSection struct {
	Listen string `koanf:"listen"` // gRPC/HTTPS API for agents (mTLS)
	// Advertise is the address agents dial to reach the controller when it differs
	// from Listen — e.g. the controller binds 0.0.0.0 (or an overlay address) but
	// is reached through a NAT/gateway/host address (a Lima host gateway, a
	// published load-balancer). When set it (a) becomes the default endpoint baked
	// into each agent's config and (b) seeds an extra SAN on the server cert so the
	// agent's TLS handshake validates the dialed host. Empty ⇒ Listen is used.
	Advertise string         `koanf:"advertise"`
	WebUI     string         `koanf:"webui"`     // Web UI bind (deferred on MVP; reserved)
	Store     string         `koanf:"store"`     // path to the sqlite state db
	Metrics   string         `koanf:"metrics"`   // Prometheus /metrics bind (mgmt addr only)
	AgentBin  string         `koanf:"agent_bin"` // wgfleet-agent binary installed during UI-triggered provisioning
	PKI       PKISection     `koanf:"pki"`
	Secrets   SecretsSection `koanf:"secrets"` // backing store for secret:// references
	// StalenessAfter marks a Ready/Reconciling node Degraded when it has not
	// reported status for this long (a silent/dead agent). 0 disables the sweep.
	StalenessAfter time.Duration `koanf:"staleness_after"`
	// SessionTTL is the web panel's sliding session lifetime. 0 ⇒ default (7d).
	SessionTTL time.Duration `koanf:"session_ttl"`
}

// SecretsSection configures the provider backing secret:// references. When
// SOPSFile is set, secret://NAME is resolved by decrypting that SOPS-encrypted
// YAML file (age/PGP/KMS recipients) at startup and looking NAME up among its
// keys. Empty ⇒ the env-backed MVP provider (WGFLEET_SECRET_<NAME>).
type SecretsSection struct {
	SOPSFile string `koanf:"sops_file"` // path to a SOPS-encrypted YAML secrets file
}

// DefaultStalenessAfter is the default staleness threshold when unset (3× the
// default agent reconcile interval).
const DefaultStalenessAfter = 3 * time.Minute

// Staleness returns the configured staleness threshold, or the default when the
// key is absent. A negative value is treated as disabled (returns 0).
func (c ControllerConfig) Staleness() time.Duration {
	switch {
	case c.Controller.StalenessAfter < 0:
		return 0
	case c.Controller.StalenessAfter == 0:
		return DefaultStalenessAfter
	default:
		return c.Controller.StalenessAfter
	}
}

// DefaultSessionTTL is the web panel session lifetime when unset.
const DefaultSessionTTL = 7 * 24 * time.Hour

// WebUISessionTTL returns the configured session lifetime, or the default.
func (c ControllerConfig) WebUISessionTTL() time.Duration {
	if c.Controller.SessionTTL <= 0 {
		return DefaultSessionTTL
	}
	return c.Controller.SessionTTL
}

// PKISection configures the mTLS certificate authority used to issue node certs.
type PKISection struct {
	CACert string `koanf:"ca_cert"` // path to the CA certificate (public)
	CAKey  Secret `koanf:"ca_key"`  // reference to the CA private key (never inline in git)
}

// FleetSection is the declarative desired fleet: the set of masters and exits.
type FleetSection struct {
	Masters []MasterConfig `koanf:"masters"`
	Exits   []ExitConfig   `koanf:"exits"`
	// ZeroTierNetwork is the mgmt overlay network nodes join during bootstrap.
	ZeroTierNetwork string `koanf:"zerotier_network"`
	// MgmtSubnet is the CIDR of the management overlay (ZeroTier). When set it is
	// the authoritative trust scope the platform applies WITHOUT the operator
	// hand-listing it on every node: exits route it DIRECT (never via WARP — earlier findings
	// ) and accept it in their firewall. Empty ⇒ the broker derives the scope
	// from the individual mgmt_addr /32s of every fleet node (see MgmtCIDRs).
	MgmtSubnet string `koanf:"mgmt_subnet"`
	// MgmtOverlayMSS, when > 0, is baked into every node's agent.yaml at provisioning
	// time (agent.mgmt_overlay_mss) so the agent clamps TCP MSS on the ZeroTier
	// interface. Control-plane insurance: keeps the agent↔controller mTLS handshake
	// working even if the ZeroTier MTU is left at its 2800 default while the underlay
	// path is smaller. Recommended 1240 (matches a 1280 overlay MTU); 0 disables.
	MgmtOverlayMSS int `koanf:"mgmt_overlay_mss"`
	// MinEgressThroughputKBytes is the fleet-wide egress throughput floor in KiB/s
	// (the value is multiplied by 1024 to bytes/sec) below which an exit's active egress is considered degraded
	// (ADR-0021). mihomo's url-test is latency-only and cannot see a throttled exit
	// (the exit-3 case: 88ms latency but 25 KB/s), so the platform measures throughput
	// per exit and removes the throttled ones from the LB. 0 disables the watchdog
	// fleet-wide. Default applied when unset is DefaultMinEgressThroughputKBytes.
	// A healthy WARP exit does tens of MB/s, so 250 cleanly separates broken nodes.
	MinEgressThroughputKBytes int `koanf:"min_egress_throughput_kbytes"`
	// EgressThroughputProbeURL overrides the URL each exit downloads to measure its
	// egress throughput. Empty ⇒ the agent default (health.DefaultThroughputProbeURL).
	EgressThroughputProbeURL string `koanf:"egress_throughput_probe_url"`
	// ReconcileInterval is the fleet-wide agent reconcile cadence baked into every
	// node's agent.yaml at provisioning (agent.reconcile_interval). It governs how
	// fast drift and self-heal land. 0/unset ⇒ DefaultReconcileInterval. A per-node
	// agent.yaml value still overrides it. Resolve via AgentReconcileInterval.
	ReconcileInterval time.Duration `koanf:"reconcile_interval"`
	// ASBlacklistV4URL / ASBlacklistV6URL / ASBlacklistInterval configure the
	// scanner-ASN blacklist feed every exit refreshes to hide its WG port/SSH from
	// active VPN scanners (the per-exit enable toggle is exits[].firewall.as_blacklist).
	// They are baked fleet-wide into each agent.yaml at provisioning (agent-local
	// operational knobs, like MgmtOverlayMSS). Empty URLs / 0 interval ⇒ the asnfeed
	// defaults (C24Be/AS_Network_List, 24h).
	ASBlacklistV4URL    string        `koanf:"as_blacklist_v4_url"`
	ASBlacklistV6URL    string        `koanf:"as_blacklist_v6_url"`
	ASBlacklistInterval time.Duration `koanf:"as_blacklist_interval"`
	// RealityDefaultSNI / RealityDefaultDest are the fleet-wide camouflage target for
	// the VLESS+REALITY+XHTTP transport (ADR-0025): the SNI the link impersonates and
	// the real TLS-1.3 site the inbound borrows a cert from / falls back to for probes.
	// A per-exit exits[].reality.{server_name,dest} overrides it; empty here ⇒ a safe
	// built-in (keybroker.DefaultRealitySNI). Pick a target whose hosting ASN is
	// plausible for the exit's provider (recon 2026-06-25) — a single fleet default is
	// a starting point, but ASN-diverse exits SHOULD set it per-exit.
	RealityDefaultSNI  string `koanf:"reality_default_sni"`
	RealityDefaultDest string `koanf:"reality_default_dest"`
}

// AgentReconcileInterval returns the fleet-wide agent reconcile interval, or the
// default when unset. The provisioner bakes the result into each agent.yaml.
func (f FleetSection) AgentReconcileInterval() time.Duration {
	if f.ReconcileInterval <= 0 {
		return DefaultReconcileInterval
	}
	return f.ReconcileInterval
}

// DefaultMinEgressThroughputKBytes is the egress throughput floor applied when the
// fleet leaves min_egress_throughput_kbytes unset (0). Set the fleet key to a
// NEGATIVE value to disable the watchdog entirely.
const DefaultMinEgressThroughputKBytes = 250

// EgressThroughputFloorKBytes resolves the throughput floor (KB/s) for one exit:
// the exit's own override when set (>0), else the fleet default (0 ⇒
// DefaultMinEgressThroughputKBytes). A negative value at either level disables the
// watchdog for that exit and returns 0 (watchdog off). The keybroker converts the
// result to bytes/sec for the NodeSpec.
func (f FleetSection) EgressThroughputFloorKBytes(e ExitConfig) int {
	if e.MinEgressThroughputKBytes < 0 || (f.MinEgressThroughputKBytes < 0 && e.MinEgressThroughputKBytes == 0) {
		return 0 // explicitly disabled at exit or fleet level
	}
	if e.MinEgressThroughputKBytes > 0 {
		return e.MinEgressThroughputKBytes
	}
	if f.MinEgressThroughputKBytes > 0 {
		return f.MinEgressThroughputKBytes
	}
	return DefaultMinEgressThroughputKBytes
}

// MgmtCIDRs returns the management-overlay address scope the platform trusts for
// routing-direct and firewall-accept. It is the explicit MgmtSubnet when set,
// otherwise the host route (/32 or /128) of every master/exit mgmt_addr that
// parses as an IP, de-duplicated in a stable order (masters first, then exits).
// This is what makes ZeroTier reachability robust without the operator listing the
// overlay in each exit's whitelist/direct_cidrs by hand.
func (f FleetSection) MgmtCIDRs() []string {
	if s := strings.TrimSpace(f.MgmtSubnet); s != "" {
		if p, err := netip.ParsePrefix(s); err == nil {
			return []string{p.Masked().String()}
		}
	}
	addrs := make([]string, 0, len(f.Masters)+len(f.Exits))
	for _, m := range f.Masters {
		addrs = append(addrs, m.MgmtAddr)
	}
	for _, e := range f.Exits {
		addrs = append(addrs, e.MgmtAddr)
	}
	var out []string
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		addr, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		cidr := netip.PrefixFrom(addr, addr.BitLen()).String()
		if _, dup := seen[cidr]; dup {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}

// SSHConfig is the bootstrap SSH target for a node (Phase 0/1 only; management
// switches to mTLS once the agent is installed). The key path points to a
// private key on the controller host; it is a secret and never committed.
type SSHConfig struct {
	Host    string `koanf:"host"`
	Port    int    `koanf:"port"`
	User    string `koanf:"user"`
	KeyPath string `koanf:"key_path"`
	// HostKey pins the server's SSH host key (an authorized_keys / known_hosts
	// public-key line). Strongly recommended: bootstrap ships the node's mTLS
	// private key over SSH, so without pinning a MITM on the bootstrap path can
	// capture the node's identity. Empty falls back to trust-on-first-use.
	HostKey string `koanf:"host_key"`
	// InsecureIgnoreHostKey explicitly disables host-key verification for this
	// node's bootstrap dial (even if host_key is set). Use on trusted networks or
	// first-run bring-up where pinning is impractical; it trades away MITM
	// protection on the channel that ships the node's mTLS key. The fleet-wide
	// env override WGFLEET_SSH_INSECURE_HOST_KEY=1 does the same for every node.
	InsecureIgnoreHostKey bool `koanf:"insecure_ignore_host_key"`
}

// MasterConfig describes one master node in the fleet manifest.
type MasterConfig struct {
	Name        string            `koanf:"name"`
	MgmtAddr    string            `koanf:"mgmt_addr"`
	PublicIP    string            `koanf:"public_ip"` // public IP peers/clients reach this node at; defaults to ssh.host when empty
	ClientAWG   ClientAWGConfig   `koanf:"client_awg"`
	ClientVLESS ClientVLESSConfig `koanf:"client_vless"` // client-facing VLESS+REALITY+XHTTP (DPI-resistant alternative to client AWG)
	Routing     MasterRouting     `koanf:"routing"`
	Mihomo      MihomoConfig      `koanf:"mihomo"`  // master data-plane (mihomo) tuning
	Compose     ComposeConfig     `koanf:"compose"` // master container stack tuning
	SSH         SSHConfig         `koanf:"ssh"`     // bootstrap target
	// ClientAdminPorts opens admin UI ports (controller Web UI, mihomo dashboard)
	// on the master's mgmt address to the VPN client pool. Opt-in: empty keeps the
	// strict default (admin reachable only over the mgmt overlay). See
	// domain.MasterSpec.ClientAdminPorts for the security trade-off.
	ClientAdminPorts []int `koanf:"client_admin_ports"`
	// PublicTCPPorts are TCP ports opened to the WORLD (no interface scope) for
	// publicly reachable services — e.g. the decoy web listener on 80. Distinct from
	// ClientAdminPorts above, which is scoped to the client WG interface: anything
	// listed here is reachable from every source the drop policy would otherwise
	// block, so keep it to genuinely public services.
	PublicTCPPorts []int `koanf:"public_tcp_ports"`
	// DNSFilter enables the master-tier blocky resolver (ADR-0024): a client-facing
	// filtering resolver clients use as their DNS. It blocks + forwards local zones to
	// internal DNS (DNS.overrides conditional mappings) + forwards everything else to
	// the active exit blockys. Off ⇒ clients fall back to the exit blockys directly.
	DNSFilter bool `koanf:"dns_filter"`
	// DNS is the master resolver's config (same shape as exits[].dns). Its upstreams
	// default to the active exit blockys; the rich surface (denylists, conditional
	// local-zone mappings, caching) rides in DNS.overrides.
	DNS DNSConfig `koanf:"dns"`
}

// MihomoConfig is the operator-facing mihomo tuning for a master, including the
// generic config-customization hooks (overrides + extra files).
type MihomoConfig struct {
	RedirPort int `koanf:"redir_port"` // 0 ⇒ mihomo.DefaultRedirPort
	// HealthInterval is how often mihomo health-checks the exits in wg-best (detect /
	// route around dead exits). 0/unset ⇒ mihomo.DefaultHealthInterval (60s). Lower it
	// to fail over off a dead exit faster. Rendered to seconds in the proxy group.
	HealthInterval time.Duration `koanf:"health_interval"`
	// MaxFailedTimes is how many consecutive connection failures force an
	// out-of-band health check on a proxy group. 0 ⇒ mihomo's own default (5).
	// Raise it where some traffic legitimately fails (blocked destinations) and the
	// forced re-check is noise rather than signal.
	MaxFailedTimes int               `koanf:"max_failed_times"`
	SnifferSkip    []string          `koanf:"sniffer_skip"` // sniffer skip-domain
	Overrides      map[string]any    `koanf:"overrides"`    // deep-merged into rendered config.yaml
	ExtraFiles     []ExtraFileConfig `koanf:"extra_files"`  // additional managed files
	// DashboardURL overrides the mihomo web-dashboard download source; empty ⇒ the
	// built-in default (zashboard latest on GitHub). Point it at a reachable mirror
	// where GitHub is blocked.
	DashboardURL string `koanf:"dashboard_url"`
	// DashboardDisabled turns the web dashboard off entirely (mihomo won't try to
	// download the UI on first run). Default false ⇒ dashboard enabled.
	DashboardDisabled bool `koanf:"dashboard_disabled"`
}

// ComposeConfig is the operator-facing master container-stack tuning. Empty
// fields fall back to defaults in the compose renderer.
type ComposeConfig struct {
	WGEasyImage      string   `koanf:"wg_easy_image"` // repository (optionally :tag)
	WGEasyTag        string   `koanf:"wg_easy_tag"`   // explicit tag; overrides a tag in the image
	MihomoImage      string   `koanf:"mihomo_image"`  // repository (optionally :tag)
	MihomoTag        string   `koanf:"mihomo_tag"`    // explicit tag; overrides a tag in the image
	WGEasyWebPort    int      `koanf:"wg_easy_web_port"`
	ClientDNS        []string `koanf:"client_dns"`         // 0 ⇒ derived from exit mgmt addrs
	ClientAllowedIPs string   `koanf:"client_allowed_ips"` // inverted RFC1918 list for clients
}

// ExtraFileConfig is an operator-provisioned file written alongside the rendered
// config (e.g. an extra mihomo rule-provider list).
type ExtraFileConfig struct {
	Path    string `koanf:"path"`
	Content string `koanf:"content"`
	Secret  bool   `koanf:"secret"`
}

// DefaultMasterClientPort is the UDP port the master's client-facing AmneziaWG
// server listens on when the manifest leaves client_awg.listen_port unset. 443
// is the least conspicuous choice — client traffic blends with HTTPS.
const DefaultMasterClientPort = 443

// ClientAWGConfig is the client-facing AmneziaWG listener on a master.
type ClientAWGConfig struct {
	ListenPort  int    `koanf:"listen_port"`  // UDP; 0 ⇒ DefaultMasterClientPort. Prefer 443/51820
	AddressPool string `koanf:"address_pool"` // CIDR for client addresses
}

// ClientListenPort returns the configured master client port or the default.
func (m MasterConfig) ClientListenPort() int {
	if m.ClientAWG.ListenPort <= 0 {
		return DefaultMasterClientPort
	}
	return m.ClientAWG.ListenPort
}

// ClientVLESSEmptySNIDefault is the empty_sni default for the client-facing VLESS
// inbound: ON. An SNI-less ClientHello lifted the RU TSPU block in 100% of one
// 2026 field test (docs/research/2026-07-client-transport-dpi.md), so the client
// leg opts in by default; an operator can force it off with empty_sni: false.
const ClientVLESSEmptySNIDefault = true

// ClientVLESSFingerprintDefault / ClientVLESSMuxDefault re-export the client-leg
// uTLS/XMUX defaults from the domain layer (their rationale lives on the domain
// consts) so config, keybroker, and the web link builders all resolve to one value.
const (
	ClientVLESSFingerprintDefault = domain.ClientVLESSFingerprintDefault
	ClientVLESSMuxDefault         = domain.ClientVLESSMuxDefault
)

// clientVLESSPortLo/Hi bound the high-port window the client VLESS inbound's port
// is derived into when unset. High ports (47000+) evade the deep TLS inspection RU
// TSPU applies to 443 (2026 recon), so — unlike the AWG UDP port —
// the client TLS leg deliberately prefers a high, non-standard port.
const (
	clientVLESSPortLo = 40000
	clientVLESSPortHi = 60000
)

// ClientVLESSConfig is the operator's tuning for the master's CLIENT-FACING
// VLESS+REALITY+XHTTP inbound — a DPI-resistant alternative to client↔master
// AmneziaWG that runs alongside it. Like RealityTransportConfig, the REALITY
// x25519 keypair is generated on the master and only the pubkey is published;
// per-client UUID/short-id credentials are NOT here either — they are issued and
// revoked through the Web UI and persisted in the controller store. This carries
// only operator-facing camouflage/transport choices.
type ClientVLESSConfig struct {
	Enabled    bool   `koanf:"enabled"`
	ListenPort int    `koanf:"listen_port"` // TCP; 0 ⇒ a per-master high port derived in [40000,60000]
	DestDomain string `koanf:"dest_domain"` // camouflage target host; empty ⇒ fleet default / SNI
	DestPort   int    `koanf:"dest_port"`   // camouflage target port; 0 ⇒ 443
	SNI        string `koanf:"sni"`         // camouflage SNI (ClientHello); empty ⇒ dest_domain / fleet default
	// Mode is the REALITY transport: "xhttp" (default; packet-up addresses the
	// behavioural throttling RU TSPU applies to persistent TLS flows) or "vision"
	// (classic TCP + xtls-rprx-vision, no XHTTP layer).
	Mode string `koanf:"mode"`
	// EmptySNI accepts/sends a ClientHello with NO SNI extension. Pointer so an unset
	// value defaults ON (ClientVLESSEmptySNIDefault) — the client leg's strongest
	// reported RU-TSPU bypass; set `empty_sni: false` to force it off.
	EmptySNI *bool `koanf:"empty_sni"`
	// Fingerprint is the client's uTLS ClientHello fingerprint (vless:// `fp`, mihomo
	// `client-fingerprint`): "firefox" (default; off the chrome signature RU TSPU
	// flags first), "chrome", "safari", … or "none" to omit it. Empty ⇒
	// ClientVLESSFingerprintDefault.
	Fingerprint string `koanf:"fingerprint"`
	// Mux enables XMUX (XHTTP connection reuse) in the generated client profile.
	// Pointer so an unset value defaults ON (ClientVLESSMuxDefault): amortizing the
	// REALITY handshake across streams is the strongest handshake-parallelism-freeze
	// mitigation. Only effective in xhttp mode. Set `mux: false` to disable.
	Mux *bool `koanf:"mux"`
	// AllowIPv6 lets xray resolve the camouflage dest over IPv6. Default false ⇒
	// pinned to IPv4 (the data plane is IPv4-only, an earlier finding).
	AllowIPv6 bool   `koanf:"allow_ipv6"`
	XHTTPPath string `koanf:"xhttp_path"` // XHTTP path; empty ⇒ "/"
	Image     string `koanf:"image"`      // xray image (repo, optionally :tag); empty ⇒ default pinned
	Tag       string `koanf:"tag"`        // explicit tag; overrides a tag in image
	// RouteThroughCIDRs are the internal networks a CLIENT must route THROUGH the
	// tunnel rather than bypass (v2rayTun & most clients send private/LAN ranges
	// DIRECT by default, so the master's ZT overlay and operator work-nets behind it
	// are otherwise unreachable over the VPN). The controller builds a v2rayTun
	// "routing" object from these and both shows it in the Web UI (base64 + QR) and
	// serves it in the subscription's `routing` response header, so an importing
	// client reaches them. Empty ⇒ no routing object (bare vless; the client's own
	// routing applies). Operator-managed — list the CIDRs the master can actually
	// reach (its ZT mgmt subnet + any nets it forwards to).
	RouteThroughCIDRs []string `koanf:"route_through_cidrs"`
}

// DestHostPort returns the camouflage target as "host:port" (dest_port 0 ⇒ 443),
// or "" when no domain is set — the keybroker then falls back to the fleet default
// or the SNI.
func (c ClientVLESSConfig) DestHostPort() string {
	if c.DestDomain == "" {
		return ""
	}
	port := c.DestPort
	if port == 0 {
		port = DefaultRealityDestPort
	}
	return fmt.Sprintf("%s:%d", c.DestDomain, port)
}

// ResolvedEmptySNI resolves the empty_sni tri-state: unset ⇒ default (ON).
func (c ClientVLESSConfig) ResolvedEmptySNI() bool {
	if c.EmptySNI == nil {
		return ClientVLESSEmptySNIDefault
	}
	return *c.EmptySNI
}

// ResolvedFingerprint resolves the client uTLS fingerprint: unset ⇒ the off-chrome
// default; any explicit value (including "none") is honoured verbatim.
func (c ClientVLESSConfig) ResolvedFingerprint() string {
	if c.Fingerprint == "" {
		return ClientVLESSFingerprintDefault
	}
	return c.Fingerprint
}

// ResolvedMux resolves the mux tri-state: unset ⇒ default (ON).
func (c ClientVLESSConfig) ResolvedMux() bool {
	if c.Mux == nil {
		return ClientVLESSMuxDefault
	}
	return *c.Mux
}

// ClientVLESSListenPort returns the configured client VLESS port, or a stable
// per-master port derived deterministically from the master name into the high
// window [40000,60000] when unset (so it survives restarts and differs per node).
func (m MasterConfig) ClientVLESSListenPort() int {
	if m.ClientVLESS.ListenPort > 0 {
		return m.ClientVLESS.ListenPort
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte("wgfleet-client-vless-port|" + m.Name))
	span := uint32(clientVLESSPortHi - clientVLESSPortLo + 1)
	return clientVLESSPortLo + int(h.Sum32()%span)
}

// MasterRouting captures the master's geo-routing / load-balancing intent.
type MasterRouting struct {
	DirectCIDRs []string `koanf:"direct_cidrs"` // routed DIRECT, never via an exit
	DirectGeo   []string `koanf:"direct_geo"`   // geo codes routed DIRECT, e.g. ["RU"]
	// Balance selects how the master's wg-best group picks an exit:
	//   round-robin        — load-balance, every connection cycles exits (default)
	//   consistent-hashing — load-balance, same dst → same exit (session stability)
	//   health (alias)     — same as consistent-hashing (back-compat)
	//   sticky-sessions    — load-balance, same src+dst → same exit
	//   url-test           — route everything through the lowest-latency exit (auto-best)
	//   fallback           — primary exit, fail over to the next on timeout
	Balance string `koanf:"balance"`
	// ReserveExits names the exits this master keeps as a SECOND tier: traffic uses
	// them only when every primary exit is down (ADR-0029). The primary tier is
	// everything not listed here, so a newly added exit defaults to primary and no
	// exit can fall out of both tiers. Entries are manifest exit names ("1cnode004"),
	// not rendered proxy names ("1cnode004-reality") — the transport suffix is an
	// implementation detail. Empty ⇒ a single flat group, exactly as before.
	ReserveExits []string `koanf:"reserve_exits"`
}

// Exit WG listen-port derivation. When the manifest leaves listen_port unset, the
// port is derived deterministically per exit within this range, so every exit
// listens on a different, stable, non-obvious port (avoids fingerprinting the
// whole fleet by a single fixed master↔exit port) instead of all sharing 51820.
// The range stays below the Linux ephemeral range (32768+) and above privileged
// ports; the value is stable per node name (the master must dial the same port
// the exit binds, and the firewall must open it).
const (
	exitPortRangeLo = 20000
	exitPortRangeHi = 32000
)

// derivedExitPort maps an exit name to a stable UDP port in [exitPortRangeLo,
// exitPortRangeHi]. FNV-1a is enough: this is obfuscation/spread, not security.
func derivedExitPort(name string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	span := uint32(exitPortRangeHi - exitPortRangeLo + 1)
	return exitPortRangeLo + int(h.Sum32()%span)
}

// ExitConfig describes one exit node in the fleet manifest.
type ExitConfig struct {
	Name           string   `koanf:"name"`
	Region         string   `koanf:"region"`
	Egress         string   `koanf:"egress"`          // "warp" | "direct" (preferred)
	EgressFallback []string `koanf:"egress_fallback"` // ordered fallbacks for censorship-adaptive failover (ADR-0017), e.g. [direct]; empty ⇒ no failover
	WARPMTU        int      `koanf:"warp_mtu"`        // WARP interface MTU; 0 ⇒ computed (1440). Set when the real WARP path is smaller (an earlier finding: 1320-1420)
	// LinkMTU is the physical/path MTU of the master↔exit link — the largest packet
	// that reaches this exit without fragmentation. Measure it with `ping -M do -s N
	// <exit-ip>` from the master (path MTU = largest passing N + 28) and set the
	// result here. 0 ⇒ assume 1500. When an exit's real path is below 1500 (a DC
	// overlay, PPPoE, a narrow transit), the master↔exit AmneziaWG carrier packets
	// (tunnel MTU + ~140 obfuscation overhead) black-hole on that path — the
	// "tunnel up but intermittently hangs" symptom. Setting LinkMTU
	// lowers BOTH ends of this exit's tunnel AND the client interface (so client
	// payloads never exceed what survives the narrowest exit, ADR-0014 sequential
	// model), exactly as warp_mtu does for the WARP leg.
	LinkMTU int `koanf:"link_mtu"`
	// MinEgressThroughputKBytes overrides the fleet egress throughput floor (KB/s)
	// for this exit (ADR-0021): >0 custom floor, 0 inherits the fleet default,
	// negative disables the watchdog for this exit. See FleetSection.
	MinEgressThroughputKBytes int            `koanf:"min_egress_throughput_kbytes"`
	PublicIP                  string         `koanf:"public_ip"`   // public IP the master dials this exit at (WG endpoint); defaults to ssh.host when empty
	ListenPort                int            `koanf:"listen_port"` // WG server port; 0 ⇒ DefaultExitListenPort
	AddressPool               string         `koanf:"address_pool"`
	MgmtAddr                  string         `koanf:"mgmt_addr"` // ZT overlay address (admin/metrics/DNS bind)
	DNSFilter                 bool           `koanf:"dns_filter"`
	DNS                       DNSConfig      `koanf:"dns"` // optional rich blocky tuning + custom config
	Firewall                  FirewallConfig `koanf:"firewall"`
	SSH                       SSHConfig      `koanf:"ssh"` // bootstrap target
	// Transports declares which master↔exit transports this exit runs and tunes each
	// (ADR-0025): two sections — awg and reality — each gated by its `enabled` flag.
	// Both disabled ⇒ AWG-only (back-compat). Both enabled ⇒ dual-transport (warm).
	Transports TransportsConfig `koanf:"transports"`
	// ActiveTransport is the transport the master routes to (must be enabled).
	// Empty ⇒ the first enabled transport. The operator flips this (or via the UI)
	// to switch the live path between AWG and REALITY.
	ActiveTransport string `koanf:"active_transport"`
	// PerTunnelKey drives the ADR-0030 migration from the master's single shared
	// WireGuard identity to a per-tunnel one, for THIS exit only. It is deliberately
	// operator-controlled and per-exit so the fleet rolls one node at a time with a
	// verification point between every step; nothing about it is automatic.
	//
	// Each step moves exactly ONE side of the tunnel, which is what makes it
	// rollback-safe — see domain.PerTunnelKeyPhase.
	PerTunnelKey string `koanf:"per_tunnel_key"`
}

// PerTunnelKeyPhase returns the exit's ADR-0030 migration phase, defaulting to
// PerTunnelKeyOff (the pre-ADR-0030 shared-key behaviour) when unset.
func (e ExitConfig) PerTunnelKeyPhase() domain.PerTunnelKeyPhase {
	if e.PerTunnelKey == "" {
		return domain.PerTunnelKeyOff
	}
	return domain.PerTunnelKeyPhase(e.PerTunnelKey)
}

// TransportsConfig holds the two master↔exit transport sections (ADR-0025). Each
// section is gated by its own `enabled` flag, so the operator turns a transport on
// (and tunes it) in one place; the active transport is selected by the enclosing
// ExitConfig.ActiveTransport.
type TransportsConfig struct {
	AWG     AWGTransportConfig     `koanf:"awg"`
	Reality RealityTransportConfig `koanf:"reality"`
}

// AWGTransportConfig tunes the kernel AmneziaWG transport (awg-quick awg0 on the
// exit, a mihomo wireguard proxy on the master).
type AWGTransportConfig struct {
	Enabled    bool `koanf:"enabled"`
	ListenPort int  `koanf:"listen_port"` // WG server UDP port; 0 ⇒ stable-random derived from the exit name (as on other exits)
}

// RealityTransportConfig is the operator's per-exit tuning for the VLESS+REALITY+
// XHTTP transport (ADR-0025). The REALITY x25519 keypair, UUID and short-id are NOT
// here — the exit generates its keypair locally and the controller derives the
// shared identifiers; this carries only operator-facing camouflage choices.
type RealityTransportConfig struct {
	Enabled    bool   `koanf:"enabled"`
	ListenPort int    `koanf:"listen_port"` // VLESS port; 0 ⇒ DefaultRealityListenPort (443). Must differ from the AWG port so both run warm.
	DestDomain string `koanf:"dest_domain"` // camouflage target host; empty ⇒ fleet default / SNI
	DestPort   int    `koanf:"dest_port"`   // camouflage target port; 0 ⇒ 443
	SNI        string `koanf:"sni"`         // camouflage SNI (ClientHello); empty ⇒ dest_domain / fleet default
	// Mode is the REALITY transport: "xhttp" (default; packet-up dodges the volume
	// freeze) or "vision" (classic TCP + xtls-rprx-vision, no XHTTP). Flip to roll
	// back/forward quickly when isolating XHTTP interop.
	Mode string `koanf:"mode"`
	// Fingerprint is the master-side uTLS ClientHello fingerprint (mihomo
	// client-fingerprint): "chrome" (default), "firefox", "safari", … or "none" to
	// omit it and fall back to the Go-default fingerprint. Against heuristic DPI
	// (RU TSPU 2026) operators report firefox/none surviving where chrome is flagged.
	Fingerprint string `koanf:"fingerprint"`
	// EmptySNI accepts/sends a ClientHello with NO SNI extension (server serverNames
	// gains "", the master sends the exit IP as a placeholder so uTLS omits SNI).
	// Reported to bypass the RU TSPU heuristic block where changing the SNI does not.
	EmptySNI bool `koanf:"empty_sni"`
	// Mux enables XHTTP connection reuse (XMUX, mihomo xhttp-opts.reuse-settings) on
	// the master's reality proxy: many client streams ride one underlying XHTTP
	// connection, so the per-connection REALITY handshake + dest-steal is paid once
	// and amortized instead of on every request (mihomo's default opens a fresh
	// connection per request). Client-side only — xray needs no change. NB: this is
	// XMUX (HTTP framing), NOT sing-mux/smux (which is incompatible with xray). Only
	// effective in xhttp mode; ignored for vision (TCP). Default false.
	Mux bool `koanf:"mux"`
	// AllowIPv6 lets xray resolve the camouflage dest (and egress) over IPv6. Default
	// false ⇒ xray is pinned to IPv4 (queryStrategy UseIPv4): the exit data plane is
	// IPv4-only (no IPv6 egress, an earlier finding), so a dest that resolves AAAA-only (e.g.
	// some Fastly anycast) would otherwise black-hole the REALITY steal/egress. Set
	// true only on an exit that genuinely has working IPv6 egress.
	AllowIPv6 bool   `koanf:"allow_ipv6"`
	XHTTPPath string `koanf:"xhttp_path"` // XHTTP path; empty ⇒ /<short-id>
	Image     string `koanf:"image"`      // xray image; empty ⇒ default pinned
}

// DestHostPort returns the REALITY camouflage target as "host:port" from the split
// dest_domain/dest_port fields (dest_port 0 ⇒ 443), or "" when no domain is set —
// the keybroker then falls back to the fleet default or the SNI.
func (r RealityTransportConfig) DestHostPort() string {
	if r.DestDomain == "" {
		return ""
	}
	port := r.DestPort
	if port == 0 {
		port = DefaultRealityDestPort
	}
	return fmt.Sprintf("%s:%d", r.DestDomain, port)
}

// DefaultRealityDestPort is the camouflage target port assumed when dest_port is
// unset — 443, the real TLS site the REALITY inbound borrows a handshake from.
const DefaultRealityDestPort = 443

// EnabledTransports resolves the exit's enabled transport set into domain values,
// defaulting to AWG-only when the manifest enables neither section (back-compat).
func (e ExitConfig) EnabledTransports() []domain.MasterTransport {
	var out []domain.MasterTransport
	if e.Transports.AWG.Enabled {
		out = append(out, domain.TransportAWG)
	}
	if e.Transports.Reality.Enabled {
		out = append(out, domain.TransportRealityXHTTP)
	}
	if len(out) == 0 {
		return []domain.MasterTransport{domain.TransportAWG}
	}
	return out
}

// ResolvedActiveTransport returns the active transport, defaulting to the first
// enabled one when the manifest leaves it empty.
func (e ExitConfig) ResolvedActiveTransport() domain.MasterTransport {
	if e.ActiveTransport != "" {
		return domain.MasterTransport(e.ActiveTransport)
	}
	return e.EnabledTransports()[0]
}

// DNSConfig is the operator's optional tuning for the exit's blocky resolver.
// Safety (loopback + mgmt-only binds) is enforced by the renderer regardless;
// these fields cover defaults and customization. The rich blocky surface
// (denylists, conditional mappings, caching) goes through Overrides/ExtraFiles.
type DNSConfig struct {
	Image      string            `koanf:"image"`      // container repository (optionally :tag); default spx01/blocky
	Tag        string            `koanf:"tag"`        // explicit tag; overrides a tag in image
	Upstreams  []string          `koanf:"upstreams"`  // default upstream group; safe defaults if empty
	Allowlist  []string          `koanf:"allowlist"`  // domains never blocked (platform infra auto-added)
	Prometheus *bool             `koanf:"prometheus"` // expose /metrics; default true
	Ports      DNSPortsConfig    `koanf:"ports"`      // per-protocol ports (0 ⇒ renderer default)
	Overrides  map[string]any    `koanf:"overrides"`  // deep-merged into rendered config.yml
	ExtraFiles []ExtraFileConfig `koanf:"extra_files"`
}

// DNSPortsConfig overrides blocky's per-protocol listen ports. A zero value uses
// the renderer default (dns 53, tls 853, http 4000; https disabled).
type DNSPortsConfig struct {
	DNS   int `koanf:"dns"`
	TLS   int `koanf:"tls"`
	HTTPS int `koanf:"https"`
	HTTP  int `koanf:"http"`
}

// WGListenPort returns the operator-configured exit listen port, or a stable
// per-node port derived from the exit name when unset (randomized within a
// reasonable range so exits don't all share one fixed port).
func (e ExitConfig) WGListenPort() int {
	if p := e.Transports.AWG.ListenPort; p > 0 {
		return p
	}
	if e.ListenPort > 0 { // legacy top-level listen_port (pre-two-section schema)
		return e.ListenPort
	}
	return derivedExitPort(e.Name)
}

// FirewallConfig is the nftables policy intent for an exit node.
type FirewallConfig struct {
	ASBlacklist bool     `koanf:"as_blacklist"`
	Whitelist   []string `koanf:"whitelist"`
	// PublicTCPPorts are TCP ports opened to the WORLD (no interface scope) for
	// publicly reachable services — e.g. the decoy web listener on 80. Unlike
	// masters[].client_admin_ports (client-interface scoped), anything listed here
	// is reachable from every source, so keep it to genuinely public services.
	PublicTCPPorts []int `koanf:"public_tcp_ports"`
}

const (
	balanceRoundRobin        = "round-robin"
	balanceHealth            = "health" // alias for consistent-hashing (back-compat)
	balanceConsistentHashing = "consistent-hashing"
	balanceStickySessions    = "sticky-sessions"
	balanceURLTest           = "url-test"
	balanceFallback          = "fallback"
)

// validBalances is the set the manifest may specify for a master's wg-best group.
var validBalances = map[string]struct{}{
	balanceRoundRobin:        {},
	balanceHealth:            {},
	balanceConsistentHashing: {},
	balanceStickySessions:    {},
	balanceURLTest:           {},
	balanceFallback:          {},
}

// Validate checks the controller config for boundary violations before use.
func (c ControllerConfig) Validate() error {
	var errs []error
	if c.Controller.Listen == "" {
		errs = append(errs, errors.New("controller.listen is required"))
	}
	if c.Controller.Store == "" {
		errs = append(errs, errors.New("controller.store is required"))
	}
	if c.Controller.PKI.CACert == "" {
		errs = append(errs, errors.New("controller.pki.ca_cert is required for mTLS"))
	}
	// The ZeroTier network id is interpolated into a shell command on every node
	// during bootstrap (`zerotier-cli join <id>`). Constrain it to the exact
	// 16-hex-digit format so a malformed or malicious manifest value cannot inject
	// shell commands that run as root on every provisioned node.
	if id := c.Fleet.ZeroTierNetwork; id != "" && !zerotierNetworkID.MatchString(id) {
		errs = append(errs, fmt.Errorf("fleet.zerotier_network %q is not a valid ZeroTier network id (16 hex chars)", id))
	}
	// MgmtSubnet, when set, is rendered into routing direct-CIDR rules and the
	// firewall whitelist on every exit; reject a malformed value at startup rather
	// than letting it silently fall back to per-node /32s (or break the renderer).
	if s := c.Fleet.MgmtSubnet; s != "" {
		if _, err := netip.ParsePrefix(s); err != nil {
			errs = append(errs, fmt.Errorf("fleet.mgmt_subnet %q is not a valid CIDR: %w", s, err))
		}
	}
	if m := c.Fleet.MgmtOverlayMSS; m != 0 && (m < 536 || m > 1460) {
		errs = append(errs, fmt.Errorf("fleet.mgmt_overlay_mss %d out of range (0 to disable, else 536..1460)", m))
	}
	// A reconcile interval that is too tight hammers the control plane and the local
	// data plane (every pass probes docker/nft/listeners); too loose makes self-heal
	// and drift repair lag. Keep it in a sane band; 0/unset uses the default.
	if d := c.Fleet.ReconcileInterval; d != 0 && (d < 5*time.Second || d > time.Hour) {
		errs = append(errs, fmt.Errorf("fleet.reconcile_interval %s out of range (0 for default, else 5s..1h)", d))
	}
	// Scanner-ASN feed refresh cadence baked into agent.yaml; same band as the agent.
	if d := c.Fleet.ASBlacklistInterval; d != 0 && (d < time.Minute || d > 7*24*time.Hour) {
		errs = append(errs, fmt.Errorf("fleet.as_blacklist_interval %s out of range (0 for default, else 1m..168h)", d))
	}
	for name, u := range map[string]string{
		"fleet.as_blacklist_v4_url": c.Fleet.ASBlacklistV4URL,
		"fleet.as_blacklist_v6_url": c.Fleet.ASBlacklistV6URL,
	} {
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			errs = append(errs, fmt.Errorf("%s must be an http(s) URL, got %q", name, u))
		}
	}
	for _, m := range c.Fleet.Masters {
		if d := m.Mihomo.HealthInterval; d != 0 && (d < 5*time.Second || d > time.Hour) {
			errs = append(errs, fmt.Errorf("masters[%q].mihomo.health_interval %s out of range (0 for default, else 5s..1h)", m.Name, d))
		}
	}
	// The keybroker topology is single-master on MVP (open question #11): it peers
	// every exit to Masters[0] only, so a second master would render specs that
	// silently never establish. Fail loudly until multi-master lands.
	if len(c.Fleet.Masters) > 1 {
		errs = append(errs, fmt.Errorf("fleet: %d masters configured, but multi-master is not yet supported (keybroker peers exits to the first master only)", len(c.Fleet.Masters)))
	}
	// The Web UI and /metrics endpoints have no authentication; their only
	// protection is binding the mgmt/ZT overlay (docs/DESIGN.md §9/§10). Refuse a
	// public/unspecified bind so a misconfigured manifest can't silently expose
	// destructive node actions (drain/decommission/delete/provision) or fleet
	// topology. Set WGFLEET_ALLOW_PUBLIC_BIND=1 to override (behind your own
	// firewall/reverse proxy).
	if !allowPublicBind() {
		if err := requireMgmtBind("controller.webui", c.Controller.WebUI); err != nil {
			errs = append(errs, err)
		}
		if err := requireMgmtBind("controller.metrics", c.Controller.Metrics); err != nil {
			errs = append(errs, err)
		}
	}
	seen := make(map[string]struct{})
	for i, m := range c.Fleet.Masters {
		if m.Name == "" {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: name is required", i))
		}
		if _, dup := seen[m.Name]; dup {
			errs = append(errs, fmt.Errorf("fleet: duplicate node name %q", m.Name))
		}
		seen[m.Name] = struct{}{}
		if b := m.Routing.Balance; b != "" {
			if _, ok := validBalances[b]; !ok {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: invalid balance %q", i, b))
			}
		}
		if p := m.ClientAWG.ListenPort; p != 0 && (p < 1 || p > 65535) {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.listen_port %d out of range", i, p))
		}
		// Each direct CIDR consumes a routing priority; too many collide with the
		// fwmark rule that keeps WG handshake/reply traffic on the main table.
		if n := len(m.Routing.DirectCIDRs); n > routing.MaxDirectCIDRs {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: %d direct_cidrs exceeds the max of %d", i, n, routing.MaxDirectCIDRs))
		}
		// direct_cidrs are interpolated verbatim into the master's nft NAT ruleset
		// (`ip daddr != <cidr>` guards) and policy-routing rules; reject any non-CIDR
		// value so a typo or crafted manifest string cannot inject into the rendered
		// nft script that runs as root (CRITICAL — mirrors the whitelist's parse).
		for _, c := range m.Routing.DirectCIDRs {
			if c = strings.TrimSpace(c); c == "" {
				continue
			}
			if _, err := netip.ParsePrefix(c); err != nil {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: direct_cidrs entry %q is not a valid CIDR: %w", i, c, err))
			}
		}
		if m.ClientAWG.AddressPool != "" {
			if _, err := netip.ParsePrefix(m.ClientAWG.AddressPool); err != nil {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.address_pool %q is not a valid CIDR: %w", i, m.ClientAWG.AddressPool, err))
			}
		}
		if cv := m.ClientVLESS; cv.Enabled {
			if p := cv.ListenPort; p != 0 && (p < 1 || p > 65535) {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_vless.listen_port %d out of range", i, p))
			}
			if p := cv.DestPort; p != 0 && (p < 1 || p > 65535) {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_vless.dest_port %d out of range", i, p))
			}
			// The client VLESS (TCP) inbound and the client AWG (UDP) listener are
			// different protocols, but sharing a number is confusing and blocks moving
			// AWG to TCP later; flag a collision when the operator pins the VLESS port.
			if cv.ListenPort != 0 && cv.ListenPort == m.ClientListenPort() {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_vless.listen_port %d collides with the client AWG port", i, cv.ListenPort))
			}
			switch cv.Mode {
			case "", domain.RealityModeXHTTP, domain.RealityModeVision:
			default:
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_vless.mode %q invalid (want %q or %q)",
					i, cv.Mode, domain.RealityModeXHTTP, domain.RealityModeVision))
			}
			if err := validateRealityCamouflage(cv.SNI, cv.DestHostPort()); err != nil {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_vless: %w", i, err))
			}
			// route_through_cidrs is interpolated into the client routing object; reject
			// a non-CIDR value so a typo can't produce a broken import.
			for _, c := range cv.RouteThroughCIDRs {
				if c = strings.TrimSpace(c); c == "" {
					continue
				}
				if _, err := netip.ParsePrefix(c); err != nil {
					errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_vless.route_through_cidrs entry %q is not a valid CIDR: %w", i, c, err))
				}
			}
		}
		if err := validateMgmtAddr(m.MgmtAddr); err != nil {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: %w", i, err))
		}
	}
	for i, e := range c.Fleet.Exits {
		if e.Name == "" {
			errs = append(errs, fmt.Errorf("fleet.exits[%d]: name is required", i))
		}
		if _, dup := seen[e.Name]; dup {
			errs = append(errs, fmt.Errorf("fleet: duplicate node name %q", e.Name))
		}
		seen[e.Name] = struct{}{}
		if !domain.EgressMethod(e.Egress).Valid() {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): invalid egress %q", i, e.Name, e.Egress))
		}
		// link_mtu is the physical master↔exit path MTU; a link below the IPv6
		// minimum (1280) can't carry the tunnel reliably, and above 1500 is never a
		// real Ethernet path. 0 means "assume 1500".
		if m := e.LinkMTU; m != 0 && (m < wg.MinTunnelMTU || m > wg.DefaultPhysicalMTU) {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): link_mtu %d out of range (0 to assume %d, else %d..%d)",
				i, e.Name, m, wg.DefaultPhysicalMTU, wg.MinTunnelMTU, wg.DefaultPhysicalMTU))
		}
		if m := e.WARPMTU; m != 0 && (m < wg.MinTunnelMTU || m > wg.DefaultPhysicalMTU) {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): warp_mtu %d out of range (0 to compute, else %d..%d)",
				i, e.Name, m, wg.MinTunnelMTU, wg.DefaultPhysicalMTU))
		}
		// address_pool is interpolated verbatim into the exit's nft MASQUERADE rule
		// (ClientCIDR) and policy-routing scope; reject a non-CIDR value so a typo or
		// crafted manifest string can never inject into the rendered nft/ip ruleset.
		if e.AddressPool != "" {
			if _, err := netip.ParsePrefix(e.AddressPool); err != nil {
				errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): address_pool %q is not a valid CIDR: %w", i, e.Name, e.AddressPool, err))
			}
		}
		if err := validateMgmtAddr(e.MgmtAddr); err != nil {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): %w", i, e.Name, err))
		}
		// Transport set (ADR-0025): the active transport must be one of the enabled
		// sections. Neither section enabled defaults to AWG-only.
		activeFound := false
		active := e.ResolvedActiveTransport()
		for _, t := range e.EnabledTransports() {
			if t == active {
				activeFound = true
			}
		}
		if !activeFound {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): active_transport %q is not an enabled transport %v",
				i, e.Name, active, e.EnabledTransports()))
		}
		r := e.Transports.Reality
		if p := r.ListenPort; p != 0 && (p < 1 || p > 65535) {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): transports.reality.listen_port %d out of range", i, e.Name, p))
		}
		if p := r.DestPort; p != 0 && (p < 1 || p > 65535) {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): transports.reality.dest_port %d out of range", i, e.Name, p))
		}
		// Both transports run warm side by side; their listen ports must differ.
		if e.Transports.AWG.Enabled && r.Enabled && r.ListenPort != 0 && r.ListenPort == e.WGListenPort() {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): transports.reality.listen_port %d collides with the AWG port", i, e.Name, r.ListenPort))
		}
		switch r.Mode {
		case "", domain.RealityModeXHTTP, domain.RealityModeVision:
		default:
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): transports.reality.mode %q invalid (want %q or %q)",
				i, e.Name, r.Mode, domain.RealityModeXHTTP, domain.RealityModeVision))
		}
		if err := validateRealityCamouflage(r.SNI, r.DestHostPort()); err != nil {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): %w", i, e.Name, err))
		}
		if !e.PerTunnelKeyPhase().Valid() {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): per_tunnel_key %q invalid (want %q, %q, %q or %q)",
				i, e.Name, e.PerTunnelKey, domain.PerTunnelKeyOff, domain.PerTunnelKeyDual,
				domain.PerTunnelKeySwitch, domain.PerTunnelKeyOn))
		}
	}
	if err := validateProbeURL(c.Fleet.EgressThroughputProbeURL); err != nil {
		errs = append(errs, err)
	}
	if err := validateRealityCamouflage(c.Fleet.RealityDefaultSNI, c.Fleet.RealityDefaultDest); err != nil {
		errs = append(errs, fmt.Errorf("fleet: %w", err))
	}
	if err := c.validateReserveExits(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validateReserveExits rejects any masters[].routing.reserve_exits entry that
// names no declared exit. A typo must fail loudly: silently ignoring it would
// leave the node in the primary tier, which is the opposite of what the
// operator asked for. Every bad entry is accumulated (via errors.Join, like the
// rest of Validate()) rather than stopping at the first one, so an operator
// with several typos sees all of them on one deploy instead of fixing them one
// redeploy at a time.
func (c ControllerConfig) validateReserveExits() error {
	declared := make(map[string]struct{}, len(c.Fleet.Exits))
	for _, e := range c.Fleet.Exits {
		declared[e.Name] = struct{}{}
	}
	var errs []error
	for _, m := range c.Fleet.Masters {
		for _, name := range m.Routing.ReserveExits {
			if _, ok := declared[name]; !ok {
				errs = append(errs, fmt.Errorf("master %q: reserve_exits references unknown exit %q", m.Name, name))
			}
		}
	}
	return errors.Join(errs...)
}

// validateRealityCamouflage sanity-checks a REALITY camouflage SNI and dest
// (ADR-0025). The SNI must be a bare hostname (no scheme/port/path); the dest, when
// set, must be host:port. Both are rendered into the xray/mihomo config, so a typo
// here would silently break the REALITY handshake — catch it at load.
func validateRealityCamouflage(sni, dest string) error {
	if sni != "" {
		if strings.ContainsAny(sni, "/: ") {
			return fmt.Errorf("reality server_name %q must be a bare hostname (no scheme, port, or path)", sni)
		}
	}
	if dest != "" {
		host, port, err := net.SplitHostPort(dest)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("reality dest %q must be host:port", dest)
		}
	}
	return nil
}

// validateMgmtAddr rejects a non-empty mgmt_addr that is not a bare IP. The value
// is baked into the agent's systemd ExecStart (--metrics <addr>:9301), used as a
// bind address, and built into URLs; requiring a plain IP both catches typos and
// closes a systemd-unit / shell injection vector (a newline or space in the addr).
func validateMgmtAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if _, err := netip.ParseAddr(addr); err != nil {
		return fmt.Errorf("mgmt_addr %q is not a valid IP address: %w", addr, err)
	}
	return nil
}

// validateProbeURL rejects a non-empty egress_throughput_probe_url that is not a
// plain http(s) URL with a host. The exit fetches it with curl through its egress;
// restricting the scheme/host stops a file:// read or an internal-metadata SSRF
// from a crafted manifest (ADR-0021).
func validateProbeURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("fleet.egress_throughput_probe_url %q is not a valid URL: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("fleet.egress_throughput_probe_url %q must be an http(s) URL with a host", raw)
	}
	return nil
}

// allowPublicBind reports whether the operator has explicitly opted out of the
// mgmt-bind requirement for the admin surface.
func allowPublicBind() bool {
	switch os.Getenv("WGFLEET_ALLOW_PUBLIC_BIND") {
	case "1", "true", "TRUE", "yes":
		return true
	default:
		return false
	}
}

// RequireMgmtBind is the exported mgmt-bind guard for binaries other than the
// controller — notably the agent's --metrics endpoint, which is just as
// unauthenticated and leaks fleet topology if exposed. It honors the same
// WGFLEET_ALLOW_PUBLIC_BIND override and treats an empty address as disabled.
func RequireMgmtBind(field, listen string) error {
	if allowPublicBind() {
		return nil
	}
	return requireMgmtBind(field, listen)
}

// requireMgmtBind rejects a listen address that is reachable from the public
// internet. An empty address (endpoint disabled) is fine; a hostname is left to
// the operator (we can't resolve it safely at config time). Unspecified
// (0.0.0.0 / ::) and global-unicast IPs are refused; loopback, private (RFC1918),
// link-local and unique-local addresses pass as mgmt/ZT-overlay binds.
func requireMgmtBind(field, listen string) error {
	if listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// No port? Treat the whole value as the host.
		host = listen
	}
	if host == "" {
		return fmt.Errorf("%s %q binds all interfaces (empty host); bind the mgmt/ZT address only "+
			"(or set WGFLEET_ALLOW_PUBLIC_BIND=1)", field, listen)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// A hostname — can't classify without resolving; trust the operator.
		return nil
	}
	if addr.IsUnspecified() {
		return fmt.Errorf("%s %q binds all interfaces (0.0.0.0/::); the unauthenticated admin surface "+
			"must bind the mgmt/ZT address only (or set WGFLEET_ALLOW_PUBLIC_BIND=1)", field, listen)
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("%s %q binds a public address; the unauthenticated admin surface must bind the "+
		"mgmt/ZT address only (or set WGFLEET_ALLOW_PUBLIC_BIND=1)", field, listen)
}
