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
	"strconv"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/logging"
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
	// LogLevel is how much the controller says: trace | debug | info | warn | error.
	// Empty means info. The --log-level flag overrides it; SIGUSR1/SIGUSR2 move it
	// on a running process (see internal/logging).
	LogLevel string `koanf:"log_level"`
	// Advertise is the address agents dial to reach the controller when it differs
	// from Listen — e.g. the controller binds 0.0.0.0 (or an overlay address) but
	// is reached through a NAT/gateway/host address (a Lima host gateway, a
	// published load-balancer). When set it (a) becomes the default endpoint baked
	// into each agent's config and (b) seeds an extra SAN on the server cert so the
	// agent's TLS handshake validates the dialed host. Empty ⇒ Listen is used.
	Advertise string `koanf:"advertise"`
	WebUI     string `koanf:"webui"`   // Web UI bind (deferred on MVP; reserved)
	Store     string `koanf:"store"`   // path to the sqlite state db
	Metrics   string `koanf:"metrics"` // Prometheus /metrics bind (mgmt addr only)
	// ClientPortal is the bind for the client self-service portal: one person, one
	// credential, their own config and QR, and nothing else. Empty ⇒ no portal.
	//
	// It is a SEPARATE listener from WebUI on purpose. The operator UI can
	// provision, decommission and drain nodes and export an encrypted backup of the
	// whole fleet; opening that to the client pool to serve a credential page
	// would be a quiet and large escalation.
	//
	// Bind it on the MGMT address — NOT on the master's address inside the client
	// pool, which reads as the obvious choice and does not work. Two reasons, both
	// found live: the master DNATs client TCP into mihomo, and
	// masters[].client_admin_ports opens ports on the mgmt address to clients.
	// Clients get to it as long as the
	// mgmt subnet is in their AllowedIPs.
	ClientPortal string `koanf:"client_portal"`
	// ClientPortalURL is the base URL clients reach the portal on, e.g.
	// "http://10.20.0.1:8080" (the mgmt address — see ClientPortal above). The controller cannot derive it — it knows the bind,
	// not the address a phone types — and without it the operator has no link to
	// hand out, which makes the portal unreachable however well it works.
	ClientPortalURL string `koanf:"client_portal_url"`
	// ClientProfileProviders moves the AmneziaWG proxies of every device profile
	// into a proxy provider the mihomo core re-fetches every hour by itself, so a
	// change of AmneziaWG keys or generation reaches a device without its app
	// refreshing the profile. Off by default: turning it on changes the profile's
	// shape, which each device picks up on its next profile refresh.
	ClientProfileProviders bool           `koanf:"client_profile_providers"`
	AgentBin               string         `koanf:"agent_bin"` // wgfleet-agent binary installed during UI-triggered provisioning
	PKI                    PKISection     `koanf:"pki"`
	Secrets                SecretsSection `koanf:"secrets"` // backing store for secret:// references
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
	// InterfaceAnchor labels everything that belongs to an exit's interface rather
	// than to one peer on it (AmneziaWG S/H parameters, REALITY identifiers), so
	// every master derives the same values. Unset, it follows the slot-0 master's
	// name; required once there are several masters (see AnchorLabel).
	InterfaceAnchor string `koanf:"interface_anchor"`
	// ZeroTierNetwork is the mgmt overlay network nodes join during bootstrap.
	ZeroTierNetwork string `koanf:"zerotier_network"`
	// MgmtSubnet is the CIDR of the management overlay (ZeroTier). When set it is
	// the authoritative trust scope the platform applies WITHOUT the operator
	// hand-listing it on every node: exits route it DIRECT (never via WARP) and
	// accept it in their firewall. Empty ⇒ the broker derives the scope
	// from the individual mgmt_addr /32s of every fleet node (see MgmtCIDRs).
	MgmtSubnet string `koanf:"mgmt_subnet"`
	// ClientSites are the operator's own networks a device is sometimes on and
	// sometimes away from; see ClientSiteConfig.
	ClientSites []ClientSiteConfig `koanf:"client_sites"`
	// MasterDNS is the resolver configuration of EVERY master that runs one
	// (masters[].dns_filter). A device asks all its masters' resolvers at once and
	// takes the first answer, so two masters configured apart answer the same name
	// differently, by turns. See MasterDNSFor.
	MasterDNS DNSConfig `koanf:"master_dns"`
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
	// plausible for the exit's provider — a single fleet default is
	// a starting point, but ASN-diverse exits SHOULD set it per-exit.
	RealityDefaultSNI  string `koanf:"reality_default_sni"`
	RealityDefaultDest string `koanf:"reality_default_dest"`
	// Hardening is the FLEET-WIDE default host-hardening policy. Both subsystems
	// default to ON, and an individual node overrides it with its own
	// masters[].hardening / exits[].hardening. Resolve with HardeningFor.
	Hardening HardeningSection `koanf:"hardening"`
	// AWG3 is the FLEET-WIDE default for AmneziaWG 3.0 on the master↔exit tunnels,
	// overridable per exit with exits[].awg3. Resolve with AWG3For.
	//
	// Note the polarity is the OPPOSITE of Hardening: unset means OFF. Hardening
	// fails safe by being on, whereas 3.0 fails safe by being off — enabling it
	// changes the wire format of a live tunnel and requires both a 3.x kernel
	// module on the exit and a wire-v7 agent to render it. "The operator never
	// wrote this key" must therefore mean "keep speaking 2.0", never "quietly
	// switch the protocol".
	AWG3 *bool `koanf:"awg3"`

	// AWG3Key is the fleet secret the 3.x HEADER-PROTECTION key is derived from.
	// Every other AmneziaWG parameter is derived from a public, versioned salt —
	// they work by being non-default, not by being unknown. This one is a chacha20
	// key whose whole purpose is that an observer does not have it, so it may not
	// come from anything that ships in the repository.
	//
	// Required whenever header protection is actually switched on: fleet.awg3,
	// exits[].awg3, or masters[].client_awg.awg3 set to "full". The 3.x TIMERS need
	// no secret and stay available without it.
	AWG3Key Secret `koanf:"awg3_key"`
}

// HardeningSection is the opt-out from the managed host hardening: the sshd
// drop-in (key-only auth, no root password, no X11) and the fail2ban sshd jail.
// Both are ON unless explicitly set to false — an operator who never writes this
// block gets exactly the hardened fleet earlier versions gave them.
//
// The same type appears at fleet level and on each master/exit, and per-node wins.
// Hardening is a property of a particular machine, not of the fleet: the box an
// operator hand-tunes is usually one box — typically the master, which is where
// the controller sits and where they actually log in — while the exits are cattle.
// A fleet-only switch would force them to un-harden every public-facing exit to
// keep their own sshd_config on the master, which inverts the intent.
//
// The fields are *bool, not bool, because koanf cannot distinguish an omitted key
// from an explicit `false` on a value type, and here the two must differ. At fleet
// level nil means "enabled"; on a node it means "inherit the fleet". That is also
// why a node cannot merely be compared against a zero value — an explicit
// `sshd: true` on a node must beat a fleet-wide `sshd: false`.
//
// Turning a subsystem off does not merely stop managing it — the agent REMOVES the
// file wgfleet installed, so the operator's own sshd_config/jail takes effect
// rather than being shadowed by a leftover drop-in that nothing reconciles any
// more. The removal shows up in `--plan` before it happens.
type HardeningSection struct {
	SSHD     *bool `koanf:"sshd"`
	Fail2ban *bool `koanf:"fail2ban"`
}

// HardeningFor resolves one node's effective hardening policy: the node's own
// setting when it states one, else the fleet default, else enabled. It always
// returns a non-nil spec — the controller states its intent explicitly on the wire
// so an agent never has to guess, and "unset" on the wire is reserved for
// controllers that predate the knob.
func (f FleetSection) HardeningFor(node HardeningSection) *domain.HardeningSpec {
	return &domain.HardeningSpec{
		SSHD:     resolveHardening(node.SSHD, f.Hardening.SSHD),
		Fail2ban: resolveHardening(node.Fail2ban, f.Hardening.Fail2ban),
	}
}

// resolveHardening applies the node-over-fleet-over-default precedence for one
// subsystem. Default true: the fail-safe direction, so every path that forgets to
// configure something leaves the node hardened rather than exposed.
func resolveHardening(node, fleet *bool) bool {
	if node != nil {
		return *node
	}
	if fleet != nil {
		return *fleet
	}
	return true
}

// AWG3For resolves whether one exit's master↔exit tunnel runs AmneziaWG 3.0:
// the exit's own setting when it states one, else the fleet default, else OFF.
//
// Off-by-default is the whole point — see FleetSection.AWG3. This resolves the
// OPERATOR's intent only; two further gates stand between it and a node, and they
// live in different places. The CONTROLLER (keybroker.awg3Enabled) requires wire
// v7 from BOTH ends of the tunnel — the master as well as the exit, because the
// rolling upgrade walks fleet.exits and leaves masters behind as a matter of
// course. The AGENT (awgmod.CheckAWG3Supported) requires a 3.x kernel module on
// the node itself; the controller cannot check that, because a module generation
// never travels on the wire.
func (f FleetSection) AWG3For(exit ExitConfig) bool {
	if exit.AWG3 != nil {
		return *exit.AWG3
	}
	if f.AWG3 != nil {
		return *f.AWG3
	}
	return false
}

// AgentReconcileInterval returns the fleet-wide agent reconcile interval, or the
// default when unset. The provisioner bakes the result into each agent.yaml.
func (f FleetSection) AgentReconcileInterval() time.Duration {
	if f.ReconcileInterval <= 0 {
		return DefaultReconcileInterval
	}
	return f.ReconcileInterval
}

// ClientAWG3Mode is what the client-facing interface asks of AmneziaWG 3.x.
type ClientAWG3Mode string

const (
	// ClientAWG3Off keeps the leg on AmneziaWG 2.0.
	ClientAWG3Off ClientAWG3Mode = "off"
	// ClientAWG3Timers randomises the 3.x timers and nothing else: backward
	// compatible with every config already handed out.
	ClientAWG3Timers ClientAWG3Mode = "timers"
	// ClientAWG3Full adds header protection, which disconnects every client that
	// has not re-imported.
	ClientAWG3Full ClientAWG3Mode = "full"
)

// ClientAWG3 resolves the master's client-leg AmneziaWG generation, defaulting an
// unset value to off. An unrecognised value also resolves to off — validation
// rejects it at startup, and "off" is the safe reading if it ever gets past.
func (m MasterConfig) ClientAWG3() ClientAWG3Mode {
	switch ClientAWG3Mode(strings.ToLower(strings.TrimSpace(m.ClientAWG.AWG3))) {
	case ClientAWG3Timers:
		return ClientAWG3Timers
	case ClientAWG3Full:
		return ClientAWG3Full
	default:
		return ClientAWG3Off
	}
}

// ScannerFeedMode is how a master uses the scanner feed (masters[].as_blacklist).
type ScannerFeedMode string

const (
	// ScannerFeedOff renders nothing and fetches nothing.
	ScannerFeedOff ScannerFeedMode = "off"
	// ScannerFeedObserve counts and drops nothing.
	ScannerFeedObserve ScannerFeedMode = "observe"
	// ScannerFeedEnforce drops.
	ScannerFeedEnforce ScannerFeedMode = "enforce"
)

// ScannerFeed resolves masters[].as_blacklist, defaulting an unset value to off.
// An unrecognised value also resolves to off: validation rejects it at startup,
// and off is the reading that cannot lock anyone out if it ever gets past.
func (m MasterConfig) ScannerFeed() ScannerFeedMode {
	switch ScannerFeedMode(strings.ToLower(strings.TrimSpace(m.ASBlacklist))) {
	case ScannerFeedObserve:
		return ScannerFeedObserve
	case ScannerFeedEnforce:
		return ScannerFeedEnforce
	default:
		return ScannerFeedOff
	}
}

func validScannerFeedMode(v string) bool {
	switch ScannerFeedMode(strings.ToLower(strings.TrimSpace(v))) {
	case "", ScannerFeedOff, ScannerFeedObserve, ScannerFeedEnforce:
		return true
	}
	return false
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
	Name string `koanf:"name"`
	// Slot places this master in every exit's address pool and makes slot 0 the
	// base master (see FleetSection.BaseMaster). Unique per master, 0-domain.MaxMasterSlot.
	Slot        int               `koanf:"slot"`
	MgmtAddr    string            `koanf:"mgmt_addr"`
	PublicIP    string            `koanf:"public_ip"` // public IP peers/clients reach this node at; defaults to ssh.host when empty
	ClientAWG   ClientAWGConfig   `koanf:"client_awg"`
	ClientVLESS ClientVLESSConfig `koanf:"client_vless"` // client-facing VLESS+REALITY+XHTTP (DPI-resistant alternative to client AWG)
	// RealityPortal tunes the inbound exits in the exit-initiated REALITY mode dial.
	RealityPortal RealityPortalConfig `koanf:"reality_portal"`
	Routing       MasterRouting       `koanf:"routing"`
	Mihomo        MihomoConfig        `koanf:"mihomo"`  // master data-plane (mihomo) tuning
	Compose       ComposeConfig       `koanf:"compose"` // master container stack tuning
	SSH           SSHConfig           `koanf:"ssh"`     // bootstrap target
	// Hardening overrides fleet.hardening for this master. Unset keys inherit the
	// fleet default. This is the node the override exists for: the master is where
	// the controller lives and where the operator actually logs in, so it is the
	// box most likely to carry a hand-tuned sshd_config.
	Hardening HardeningSection `koanf:"hardening"`
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
	// PublicUDPPorts are UDP ports opened to the WORLD (no interface scope) — the
	// UDP sibling of PublicTCPPorts. Motivating case: a ZeroTier controller
	// co-located with this node's own member instance, which must listen on a
	// non-default port because the member already holds 9993. Same caveat as
	// above: reachable from every source the drop policy would otherwise block.
	PublicUDPPorts []int `koanf:"public_udp_ports"`
	// Whitelist are additional source CIDRs the master's input firewall always
	// accepts, regardless of port — the master-side sibling of
	// fleet.exits[].firewall.whitelist. The management overlay is merged in
	// automatically and can never be dropped by what is listed here, so a typo
	// cannot lock the control plane out of its own node.
	//
	// Motivating case: a container on a local docker bridge that must reach a
	// host-bound service (e.g. ztnet talking to a co-located ZeroTier controller's
	// TCP control API). Source-scoping it here is the safe alternative to opening
	// that port to the world via PublicTCPPorts.
	Whitelist []string `koanf:"whitelist"`
	// ASBlacklist is the scanner feed on this master's input firewall: off,
	// observe (count new inbound connections from listed networks, drop nothing)
	// or enforce (drop them). The master-side sibling of
	// fleet.exits[].firewall.as_blacklist, with a counting step in between because
	// a master is where users connect from home and mobile networks. Replies to
	// connections the master or its clients opened are never matched.
	ASBlacklist string `koanf:"as_blacklist"`
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
	// ClientViaNetns decides WHERE client traffic is intercepted:
	//
	//	"off" / unset — on the host, the way it has always worked
	//	"auto"        — inside mihomo's own network namespace, once the agent has
	//	                proved the namespace works; reverted automatically if the
	//	                client path breaks after the switch
	//	"<CIDR>"      — canary: only client sources inside that prefix take the new
	//	                path, everyone else stays on the host path
	//
	// The namespace exists to remove a whole class of failure rather than one
	// instance of it: mihomo's TPROXY reply path binds the SERVER's address:port,
	// so every UDP port the HOST holds is a silent black hole for client traffic to
	// that port. When that port is 443, client QUIC goes one-way while every
	// component metric stays green.
	ClientViaNetns string `koanf:"client_via_netns"`
	// NetnsCIDR overrides the point-to-point link between the host and that
	// namespace — a /30, host .1, namespace .2. Empty ⇒ 100.127.255.0/30 (RFC 6598,
	// chosen because 10/8 is often routed into another tunnel or private network).
	NetnsCIDR string `koanf:"netns_cidr"`
}

// ComposeConfig is the operator-facing master container-stack tuning. Empty
// fields fall back to defaults in the compose renderer.
type ComposeConfig struct {
	MihomoImage      string   `koanf:"mihomo_image"`       // repository (optionally :tag)
	MihomoTag        string   `koanf:"mihomo_tag"`         // explicit tag; overrides a tag in the image
	ClientDNS        []string `koanf:"client_dns"`         // 0 ⇒ derived from exit mgmt addrs
	ClientAllowedIPs string   `koanf:"client_allowed_ips"` // inverted RFC1918 list for clients
	// NetnsHolderImage is the image for the container that owns mihomo's network
	// namespace. Empty ⇒ the renderer's default. The holder only has to exist and
	// sleep, so any image the node already has will do — which is the point on a
	// master that cannot reach a registry.
	NetnsHolderImage string `koanf:"netns_holder_image"`
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
	// Backend selects what carries the interface: "kernel" (default, the AmneziaWG
	// module as on the exits) or "userspace" (amneziawg-go, independent of the
	// host's kernel-module generation).
	Backend string `koanf:"backend"`
	// AWG3 opts the CLIENT-facing interface into AmneziaWG 3.x. Unlike the
	// master↔exit knob (fleet.awg3) this is NOT a bool, because the two halves of
	// 3.x cost wildly different things on a leg whose peers are other people's
	// phones:
	//
	//   ""/"off"  AmneziaWG 2.0. The default.
	//   "timers"  Timer randomisation only. Every config already in a user's hands
	//             keeps working — measured against a 3.1 kernel module, an
	//             untouched 2.0 peer handshakes and passes traffic across rekeys.
	//             This is the half that carries the anti-fingerprint value.
	//   "full"    Timers plus header protection. Header protection is the one 3.x
	//             parameter a 2.0 peer cannot survive, so this is a flag day: every
	//             client must re-import before it works again.
	AWG3 string `koanf:"awg3"`

	// IPv6 decides what a client is told about IPv6. "off" (the default, and what
	// every fleet ran before this knob existed) says nothing at all: the client keeps
	// its own native IPv6, and every dual-stack destination happy eyeballs prefers —
	// Google, Cloudflare, most CDNs — leaves the tunnel while the app says
	// "connected". "block" claims ::/0 into the tunnel and has the master answer it
	// with ICMPv6 administratively-prohibited, so the client stops using v6 at all
	// and falls back to IPv4 in milliseconds.
	//
	// It is NOT "carry v6": the data plane is IPv4-only (forwarding off, mihomo
	// ipv6:false, WARP's v6 egress dead) and that is a separate project. The
	// difference between "block" and the black hole is the ICMP, and
	// nothing else — which is why this defaults off and wants a rehearsal before an
	// operator turns it on.
	IPv6 string `koanf:"ipv6"`
	// MTU overrides the client interface MTU. 0 ⇒ the controller derives it from
	// the hop chain (clientFacingMTU), which is the right answer in almost every
	// case; set it only to pin a value the derivation cannot know about.
	MTU int `koanf:"mtu"`
	// Keepalive is what generated client configs put in PersistentKeepalive.
	// Empty ⇒ 25 seconds, the value every WireGuard deployment uses. A bare number
	// pins one interval; a "min-max" band gives each credential its own stable
	// value, which removes the fleet-wide lockstep an observer could use to join
	// our clients to one another. Raise it with care: it must stay under the
	// shortest NAT UDP timeout on the path or the master loses reachability to
	// idle clients.
	Keepalive string `koanf:"keepalive"`
	// DNS is what generated client configs point at. Empty ⇒ inherit the
	// compose-era compose.client_dns, so an existing manifest keeps working when
	// the interface changes hands.
	DNS []string `koanf:"dns"`
	// AllowedIPs is what generated client configs route into the tunnel, written
	// verbatim. The escape hatch: set it and nothing below is computed. Empty ⇒
	// inherit compose.client_allowed_ips (split on commas). An IPv6 default route
	// is rejected: the data plane is IPv4-only and "::/0" black-holes dual-stack
	// clients.
	AllowedIPs []string `koanf:"allowed_ips"`
	// ExcludeFromTunnel are networks a client must NOT send into the tunnel, so
	// they stay on its own local network. The default 0.0.0.0/0 swallows every
	// private range, which is why a client at home cannot reach a service on
	// another subnet of its own LAN while connected.
	//
	// The controller expands "everything except these" into the explicit list
	// AllowedIPs requires — the protocol has no way to say "except". This is
	// expansion, not policy: which ranges are worth excluding is the operator's
	// judgement about the networks their users sit on, nothing is assumed, and the
	// expanded result is shown in the plan and in the Web UI so it can be checked.
	//
	// Empty ⇒ no expansion at all and the default route stands, which is what
	// every WireGuard config means by "everything".
	ExcludeFromTunnel []string `koanf:"exclude_from_tunnel"`
	// RouteThroughCIDRs are networks put BACK into the tunnel after the exclusion
	// above — an operator subnet that sits inside an excluded range, or the
	// management overlay. Same name and meaning as the client_vless knob.
	// Meaningless without exclude_from_tunnel, since nothing has been taken out.
	RouteThroughCIDRs []string `koanf:"route_through_cidrs"`
}

// ClientListenPort returns the configured master client port or the default.
func (m MasterConfig) ClientListenPort() int {
	if m.ClientAWG.ListenPort <= 0 {
		return DefaultMasterClientPort
	}
	return m.ClientAWG.ListenPort
}

// ClientAWGEnabled reports whether the master has a client-facing AmneziaWG
// interface: it does exactly when client_awg.address_pool is set, since the
// interface is rendered from the pool.
func (m MasterConfig) ClientAWGEnabled() bool { return m.ClientAWG.AddressPool != "" }

// ClientAWGBackend resolves the data-plane backend for the client interface,
// defaulting an unset value to the kernel module.
func (m MasterConfig) ClientAWGBackend() domain.ClientWGBackend {
	if m.ClientAWG.Backend == "" {
		return domain.ClientWGBackendKernel
	}
	return domain.ClientWGBackend(m.ClientAWG.Backend)
}

// ClientAWGMTU returns the operator's MTU override, or 0 when the controller
// should derive it.
func (m MasterConfig) ClientAWGMTU() int { return m.ClientAWG.MTU }

// ClientAWGDNS resolves the client-facing DNS list, falling back to the older
// compose.client_dns key so a manifest that only sets that one keeps working.
func (m MasterConfig) ClientAWGDNS() []string {
	if len(m.ClientAWG.DNS) > 0 {
		return append([]string(nil), m.ClientAWG.DNS...)
	}
	return append([]string(nil), m.Compose.ClientDNS...)
}

// ClientAWGAllowedIPs resolves the client-facing AllowedIPs, falling back to the
// compose-era comma-separated key (split and trimmed) for the same reason.
func (m MasterConfig) ClientAWGAllowedIPs() []string {
	if len(m.ClientAWG.AllowedIPs) > 0 {
		return append([]string(nil), m.ClientAWG.AllowedIPs...)
	}
	if len(m.ClientAWG.ExcludeFromTunnel) > 0 {
		// The error cannot fire here: validateClientAWG parses the same entries at
		// startup and refuses to run with a malformed one.
		if out, err := domain.ExpandAllowedIPs(m.ClientAWG.ExcludeFromTunnel, m.ClientAWG.RouteThroughCIDRs); err == nil {
			return out
		}
	}
	var out []string
	for _, ip := range strings.Split(m.Compose.ClientAllowedIPs, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// ClientVLESSEmptySNIDefault is the empty_sni default for the client-facing VLESS
// inbound: ON. An SNI-less ClientHello lifted the RU TSPU block in every attempt
// of one field test, so the client interface opts in by default; an operator can force it off with empty_sni: false.
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
	// `client-fingerprint`): "chrome" (default; the profile that carries the
	// X25519MLKEM768 share newer REALITY requires), "firefox", "safari", … — a fixed uTLS profile: mihomo cannot
	// dial REALITY without one, so "none"/"random" are rejected. Empty ⇒
	// ClientVLESSFingerprintDefault.
	Fingerprint string `koanf:"fingerprint"`
	// Mux enables XMUX (XHTTP connection reuse) in the generated client profile.
	// Pointer so an unset value defaults ON (ClientVLESSMuxDefault): amortizing the
	// REALITY handshake across streams is the strongest handshake-parallelism-freeze
	// mitigation. Only effective in xhttp mode. Set `mux: false` to disable.
	Mux *bool `koanf:"mux"`
	// AllowIPv6 lets xray resolve the camouflage dest over IPv6. Default false ⇒
	// pinned to IPv4 (the data plane is IPv4-only).
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
	// LastResort puts this master's VLESS at the very end of a device profile's
	// fleet-wide fallback (`auto`): after every master's AmneziaWG and every other
	// master's VLESS. For a master whose TCP path is known to be bad; the inbound
	// itself is unchanged and the master's own group still offers it.
	LastResort bool `koanf:"last_resort"`
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

// ResolvedFingerprint resolves the client uTLS fingerprint: unset ⇒ the chrome
// default; any explicit value is honoured verbatim (Validate rejects the unusable ones).
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
	// exit can fall out of both tiers. Entries are manifest exit names ("exit-a"),
	// not rendered proxy names ("exit-a-reality") — the transport suffix is an
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
	Name   string `koanf:"name"`
	Region string `koanf:"region"`
	Egress string `koanf:"egress"` // "warp" | "direct" (preferred)
	// Drain keeps the exit out of the load balancer by declaration: it stays a
	// configured tunnel (the master keeps peering, existing sessions survive) but
	// carries no new client traffic, and the console cannot undrain it — the
	// manifest is the authority. For an exit that is down at its hoster, or held
	// back on purpose, this is the honest place to say so: the button in the
	// console is a store flag that a re-provision clears.
	Drain          bool     `koanf:"drain"`
	EgressFallback []string `koanf:"egress_fallback"` // ordered fallbacks for censorship-adaptive failover (ADR-0017), e.g. [direct]; empty ⇒ no failover
	WARPMTU        int      `koanf:"warp_mtu"`        // WARP interface MTU; 0 ⇒ computed (1440). Set when the real WARP path is smaller (1320-1420)
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
	// Hardening overrides fleet.hardening for this exit. Unset keys inherit the
	// fleet default. Weigh an opt-out here more carefully than on a master: an exit
	// is the fleet's public-facing surface, and its SSH port faces the same scanners
	// the AS-blacklist feed exists to hide from.
	Hardening HardeningSection `koanf:"hardening"`
	// AWG3 opts this exit's master↔exit AmneziaWG tunnel into AmneziaWG 3.0
	// (header protection + randomised timers). Unset inherits fleet.awg3, which is
	// itself off by default. *bool for the same reason as Hardening: koanf cannot
	// tell an omitted key from an explicit false, and here an explicit `awg3: false`
	// on one exit must beat a fleet-wide `awg3: true`.
	//
	// Per-exit rather than fleet-only because the fleet's exits do not share a
	// kernel-module generation: 3.0 params on a 1.x module are rejected outright by
	// awg setconf and the interface never comes up.
	AWG3 *bool `koanf:"awg3"`
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
	// Lifeline is a reserve client-facing AmneziaWG interface on this exit — a
	// second way in when the master's own client interface is unreachable. Opt-in:
	// nil ⇒ no reserve interface, exactly the pre-lifeline behaviour. See
	// LifelineConfig.
	Lifeline *LifelineConfig `koanf:"lifeline"`
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
	// ExitInitiated makes the exit start the master↔exit AWG flow: the exit dials the
	// master's pinned port and the master answers only once it has heard the exit.
	// For paths whose filter cuts flows the master opens but passes flows the exit
	// opens. Default false.
	ExitInitiated bool `koanf:"exit_initiated"`
	// MasterPort pins the master's external UDP port for this tunnel; 0 ⇒ derived
	// from the master and exit names (wg.MasterPortFor). Only with ExitInitiated.
	MasterPort int `koanf:"master_port"`
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
	// client-fingerprint): "chrome" (default), "firefox", "safari", … — a fixed
	// uTLS profile; "none"/"random" are rejected (mihomo cannot dial REALITY
	// without one). Against heuristic DPI (RU TSPU 2026) operators report firefox
	// surviving where chrome is flagged.
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
	// IPv4-only (no IPv6 egress), so a dest that resolves AAAA-only (e.g.
	// some Fastly anycast) would otherwise black-hole the REALITY steal/egress. Set
	// true only on an exit that genuinely has working IPv6 egress.
	AllowIPv6 bool   `koanf:"allow_ipv6"`
	XHTTPPath string `koanf:"xhttp_path"` // XHTTP path; empty ⇒ /<short-id>
	Image     string `koanf:"image"`      // xray image; empty ⇒ default pinned
	// ExitInitiated makes the exit dial every master's portal instead of
	// listening (ADR-0038): for exits where a filter drops TCP the master opens.
	ExitInitiated bool `koanf:"exit_initiated"`
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

// IsZero reports whether the operator set nothing in the block.
func (d DNSConfig) IsZero() bool {
	return d.Image == "" && d.Tag == "" && len(d.Upstreams) == 0 && len(d.Allowlist) == 0 &&
		d.Prometheus == nil && d.Ports == (DNSPortsConfig{}) && len(d.Overrides) == 0 && len(d.ExtraFiles) == 0
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
	// PublicUDPPorts are UDP ports opened to the WORLD (no interface scope) — the
	// UDP sibling of PublicTCPPorts. Same caveat: reachable from every source.
	PublicUDPPorts []int `koanf:"public_udp_ports"`
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
	if _, err := logging.ParseLevel(c.Controller.LogLevel); err != nil {
		errs = append(errs, fmt.Errorf("controller.log_level: %w", err))
	}
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
	// The Web UI and /metrics endpoints have no authentication; their only
	// protection is binding the mgmt/ZT overlay. Refuse a
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
	// The portal's bind is checked OUTSIDE the escape hatch, unlike the admin
	// surfaces above.
	//
	// WGFLEET_ALLOW_PUBLIC_BIND exists so the Web UI can sit behind the operator's
	// own reverse proxy — a documented, reasonable thing to want. But it is one
	// process-wide switch, and while this check sat inside it, setting it for that
	// reason also authorised `client_portal: 0.0.0.0:8080`: unauthenticated
	// WireGuard private-key downloads on the public internet, gated by a token in a
	// URL. The two surfaces need different answers, so the portal does not get to
	// ride on the Web UI's exemption.
	if err := requireMgmtBind("controller.client_portal", c.Controller.ClientPortal); err != nil {
		errs = append(errs, err)
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
		errs = append(errs, validateClientAWG(i, m, c.Fleet)...)
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
			if err := validateRealityFingerprint(cv.Fingerprint); err != nil {
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
		if !validScannerFeedMode(m.ASBlacklist) {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: as_blacklist %q invalid (want %q, %q or %q)",
				i, m.ASBlacklist, ScannerFeedOff, ScannerFeedObserve, ScannerFeedEnforce))
		}
	}
	// The portal's own checks live OUTSIDE the public-bind escape hatch: a malformed
	// bind and a link the operator cannot hand out are wrong however that flag is
	// set, and WGFLEET_ALLOW_PUBLIC_BIND was introduced for the Web UI, not to
	// authorise unauthenticated key downloads on 0.0.0.0.
	errs = append(errs, validateClientPortal(c.Controller.ClientPortal, c.Controller.ClientPortalURL)...)
	errs = append(errs, validateClientPoolsDisjoint(c.Fleet.Masters)...)
	errs = append(errs, validateClientSites(c.Fleet)...)
	errs = append(errs, validateAddressPoolsDisjoint(c.Fleet)...)
	errs = append(errs, validateNodeSSH(c)...)
	errs = append(errs, validateAWG3Secret(c)...)
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
		if err := validateRealityFingerprint(r.Fingerprint); err != nil {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): transports.reality: %w", i, e.Name, err))
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
	errs = append(errs, c.validateLifeline()...)
	errs = append(errs, c.validateExitInitiated()...)
	errs = append(errs, c.validateRealityExitInitiated()...)
	for i, m := range c.Fleet.Masters {
		errs = append(errs, validateRealityPortal(i, m)...)
	}
	errs = append(errs, c.validateMasterFanout()...)
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

// validateRealityFingerprint rejects the uTLS fingerprints a REALITY dial cannot
// use. mihomo refuses REALITY without a fingerprint ("none" is a dead tunnel), and
// a random pick may land on a profile without X25519MLKEM768, which REALITY
// ≥ 26.9.8 silently hands to the camouflage dest — a tunnel that fails only on
// some restarts. Empty is fine: it resolves to the per-leg default.
func validateRealityFingerprint(fp string) error {
	switch fp {
	case "none", "random", "randomized":
		return fmt.Errorf("reality fingerprint %q unusable (mihomo REALITY needs a fixed uTLS profile, e.g. \"chrome\")", fp)
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

// requireListenAddr rejects a bind that will only fail later, in a background
// goroutine, with the controller already serving and no portal. An empty value
// means "disabled" and is fine.
func requireListenAddr(field, listen string) error {
	if listen == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%s %q is not a host:port address: %w", field, listen, err)
	}
	if port == "" {
		return fmt.Errorf("%s %q has no port", field, listen)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("%s %q has a non-numeric port %q", field, listen, port)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("%s %q: %q is not an IP address", field, listen, host)
		}
	}
	return nil
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
