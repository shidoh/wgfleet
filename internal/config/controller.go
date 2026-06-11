package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

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
	if err != nil {
		return p
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
	Listen   string     `koanf:"listen"`    // gRPC/HTTPS API for agents (mTLS)
	WebUI    string     `koanf:"webui"`     // Web UI bind (deferred on MVP; reserved)
	Store    string     `koanf:"store"`     // path to the sqlite state db
	Metrics  string     `koanf:"metrics"`   // Prometheus /metrics bind (mgmt addr only)
	AgentBin string     `koanf:"agent_bin"` // wgfleet-agent binary installed during UI-triggered provisioning
	PKI      PKISection `koanf:"pki"`
	// StalenessAfter marks a Ready/Reconciling node Degraded when it has not
	// reported status for this long (a silent/dead agent). 0 disables the sweep.
	StalenessAfter time.Duration `koanf:"staleness_after"`
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
}

// MasterConfig describes one master node in the fleet manifest.
type MasterConfig struct {
	Name      string          `koanf:"name"`
	MgmtAddr  string          `koanf:"mgmt_addr"`
	PublicIP  string          `koanf:"public_ip"` // public IP peers/clients reach this node at; defaults to ssh.host when empty
	ClientAWG ClientAWGConfig `koanf:"client_awg"`
	Routing   MasterRouting   `koanf:"routing"`
	Mihomo    MihomoConfig    `koanf:"mihomo"`  // master data-plane (mihomo) tuning
	Compose   ComposeConfig   `koanf:"compose"` // master container stack tuning
	SSH       SSHConfig       `koanf:"ssh"`     // bootstrap target
}

// MihomoConfig is the operator-facing mihomo tuning for a master, including the
// generic config-customization hooks (overrides + extra files).
type MihomoConfig struct {
	RedirPort   int               `koanf:"redir_port"`   // 0 ⇒ mihomo.DefaultRedirPort
	SnifferSkip []string          `koanf:"sniffer_skip"` // sniffer skip-domain
	Overrides   map[string]any    `koanf:"overrides"`    // deep-merged into rendered config.yaml
	ExtraFiles  []ExtraFileConfig `koanf:"extra_files"`  // additional managed files
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

// ClientAWGConfig is the client-facing AmneziaWG listener on a master.
type ClientAWGConfig struct {
	ListenPort  int    `koanf:"listen_port"`  // UDP; prefer 443/51820
	AddressPool string `koanf:"address_pool"` // CIDR for client addresses
}

// MasterRouting captures the master's geo-routing / load-balancing intent.
type MasterRouting struct {
	DirectCIDRs []string `koanf:"direct_cidrs"` // routed DIRECT, never via an exit
	DirectGeo   []string `koanf:"direct_geo"`   // geo codes routed DIRECT, e.g. ["RU"]
	Balance     string   `koanf:"balance"`      // "round-robin" | "health"
}

// DefaultExitListenPort is the UDP port an exit's WG server listens on when the
// fleet manifest leaves listen_port unset. Standard ports are less conspicuous
//.
const DefaultExitListenPort = 51820

// ExitConfig describes one exit node in the fleet manifest.
type ExitConfig struct {
	Name        string         `koanf:"name"`
	Region      string         `koanf:"region"`
	Egress      string         `koanf:"egress"`      // "warp" | "direct"
	WARPMTU     int            `koanf:"warp_mtu"`    // WARP interface MTU; 0 ⇒ computed (1440). Set when the real WARP path is smaller (an earlier finding: 1320-1420)
	PublicIP    string         `koanf:"public_ip"`   // public IP the master dials this exit at (WG endpoint); defaults to ssh.host when empty
	ListenPort  int            `koanf:"listen_port"` // WG server port; 0 ⇒ DefaultExitListenPort
	AddressPool string         `koanf:"address_pool"`
	MgmtAddr    string         `koanf:"mgmt_addr"` // ZT overlay address (admin/metrics/DNS bind)
	DNSFilter   bool           `koanf:"dns_filter"`
	DNS         DNSConfig      `koanf:"dns"` // optional rich blocky tuning + custom config
	Firewall    FirewallConfig `koanf:"firewall"`
	SSH         SSHConfig      `koanf:"ssh"` // bootstrap target
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

// WGListenPort returns the configured exit listen port or the default.
func (e ExitConfig) WGListenPort() int {
	if e.ListenPort <= 0 {
		return DefaultExitListenPort
	}
	return e.ListenPort
}

// FirewallConfig is the nftables policy intent for an exit node.
type FirewallConfig struct {
	ASBlacklist bool     `koanf:"as_blacklist"`
	Whitelist   []string `koanf:"whitelist"`
}

const (
	balanceRoundRobin = "round-robin"
	balanceHealth     = "health"
)

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
		if b := m.Routing.Balance; b != "" && b != balanceRoundRobin && b != balanceHealth {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: invalid balance %q", i, b))
		}
		if p := m.ClientAWG.ListenPort; p != 0 && (p < 1 || p > 65535) {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.listen_port %d out of range", i, p))
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
	}
	return errors.Join(errs...)
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
