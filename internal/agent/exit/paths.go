// Package exit assembles the exit-role reconcilers into a plan the engine can
// run in dry-run or apply mode. Each planner wraps a pure renderer
// (wg/netfw/routing/egress/dnsfilter) as a reconcile.Planner, so the whole
// exit node converges from one NodeSpec and every step is dry-run visible.
package exit

import "path/filepath"

// Paths are the on-node file locations the exit reconcilers manage. They are
// overridable so tests can point them at a temp dir and operators can match
// their distro layout.
type Paths struct {
	WGKey      string // node WG private key (0600, generated on-node)
	WGConf     string // AmneziaWG/WireGuard interface config
	NFT        string // rendered nftables ruleset
	WGCF       string // wgcf.conf for WARP egress (rendered by us: our MTU + Table=off)
	WARPDir    string // dir where `wgcf register`/`generate` keep account + profile
	DNS        string // blocky resolver config (config.yml)
	DNSCompose string // docker-compose.yml for the blocky container stack
	// REALITY transport (ADR-0025): the locally-generated x25519 key, the rendered
	// xray inbound config, and its compose file. Only used on exits that run the
	// reality transport; otherwise the xray planner is a no-op.
	XrayKey     string // REALITY x25519 private key (0600, generated on-node)
	XrayConfig  string // rendered xray config.json
	XrayCompose string // docker-compose.yml for the xray container
	// RoutingState records the last-applied policy-routing intent so the routing
	// steps (ip rule/sysctl/conntrack -D) run only when it changes. It lives on
	// tmpfs (/run): a reboot clears the kernel rules and the state file together,
	// forcing a clean re-apply on next reconcile.
	RoutingState string
	// ASBlacklist is the persisted scanner-ASN feed cache the firewall renders into
	// the as_blacklist sets. It lives under /var/lib (persistent), so a reboot keeps
	// the last-good list while the feed planner refreshes it on its own cadence.
	ASBlacklist string
}

// DefaultPaths returns the production-default file locations.
func DefaultPaths() Paths {
	return Paths{
		WGKey:        "/etc/wgfleet/wg.key",
		WGConf:       "/etc/amnezia/amneziawg/awg0.conf",
		NFT:          "/etc/wgfleet/wgfleet.nft",
		WGCF:         "/etc/wireguard/wgcf.conf",
		WARPDir:      "/etc/wgfleet/warp",
		DNS:          "/etc/wgfleet/blocky/config.yml",
		DNSCompose:   "/etc/wgfleet/blocky/docker-compose.yml",
		XrayKey:      "/etc/wgfleet/reality.key",
		XrayConfig:   "/etc/wgfleet/xray/config.json",
		XrayCompose:  "/etc/wgfleet/xray/docker-compose.yml",
		RoutingState: "/run/wgfleet/routing.applied",
		ASBlacklist:  "/var/lib/wgfleet/as-blacklist.lst",
	}
}

// PathsUnder roots every managed file under dir. Useful for non-root or dev runs
// (and tests) where the production /etc layout is not writable.
func PathsUnder(dir string) Paths {
	return Paths{
		WGKey:        filepath.Join(dir, "wg.key"),
		WGConf:       filepath.Join(dir, "awg0.conf"),
		NFT:          filepath.Join(dir, "wgfleet.nft"),
		WGCF:         filepath.Join(dir, "wgcf.conf"),
		WARPDir:      filepath.Join(dir, "warp"),
		DNS:          filepath.Join(dir, "blocky", "config.yml"),
		DNSCompose:   filepath.Join(dir, "blocky", "docker-compose.yml"),
		XrayKey:      filepath.Join(dir, "reality.key"),
		XrayConfig:   filepath.Join(dir, "xray", "config.json"),
		XrayCompose:  filepath.Join(dir, "xray", "docker-compose.yml"),
		RoutingState: filepath.Join(dir, "routing.applied"),
		ASBlacklist:  filepath.Join(dir, "as-blacklist.lst"),
	}
}
