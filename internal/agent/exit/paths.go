// Package exit assembles the exit-role reconcilers into a plan the engine can
// run in dry-run or apply mode. Each planner wraps a pure renderer
// (wg/netfw/routing/egress/dnsfilter) as a reconcile.Planner, so the whole
// exit node converges from one NodeSpec and every step is dry-run visible.
package exit

import (
	"path/filepath"

	"github.com/shidoh/wgfleet/internal/domain"
)

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
	// LifelineKey is the exit's LIFELINE interface WireGuard private key (0600,
	// generated on-node like WGKey). Distinct from WGKey: the lifeline fronts end
	// users, so its identity must not be the one the master↔exit tunnel peers
	// against — a lifeline key leaking from a compromised exit would otherwise hand
	// over that exit's place in the fleet as well.
	LifelineKey string
	// LifelineConf is the rendered awg-quick config for domain.LifelineInterface.
	// Its PRESENCE is also the ownership evidence the disable path reads: nothing
	// but the agent ever raises awgl0, so there is no claim file to keep (unlike the
	// master's client leg, where something else may have raised wg0 first).
	LifelineConf string
	// ClientVLESSKey is the MASTER's client-facing REALITY x25519 private key (0600,
	// generated on-node). Distinct from XrayKey (the exit's master↔exit reality key);
	// a node is either master or exit, so only one is ever used. Empty on plans that
	// don't need it. Lives here because Paths is the agent's shared on-node key store.
	ClientVLESSKey string
	// RoutingState records the last-applied policy-routing intent so the routing
	// steps (ip rule/sysctl/conntrack -D) run only when it changes. It lives on
	// tmpfs (/run): a reboot clears the kernel rules and the state file together,
	// forcing a clean re-apply on next reconcile.
	RoutingState string
	// ASBlacklist is the persisted scanner-ASN feed cache the firewall renders into
	// the as_blacklist sets. It lives under /var/lib (persistent), so a reboot keeps
	// the last-good list while the feed planner refreshes it on its own cadence.
	ASBlacklist string
	// WARPMTUCache holds the auto-probed WARP path MTU (one integer). Like the AS
	// feed it is written Apply-side by a Scheduled planner and read in Plan, so the
	// network probe never runs in dry-run. Empty ⇒ the wgcf MTU falls back to the
	// operator override or wg.DefaultWARPMTU.
	WARPMTUCache string
	// WARPEndpointState holds the WARP endpoint fallback's pick (JSON). Written
	// Apply-side by a Scheduled planner when wgcf goes without a handshake for a
	// full window, read in Plan by the WARP planner. Absent ⇒ the profile endpoint.
	WARPEndpointState string
	// NonlocalBindSysctl persists net.ipv4.ip_nonlocal_bind=1, which lets blocky
	// claim the lifeline gateway before awgl0 exists. `sysctl -w` alone does not
	// survive a reboot, and a reboot is exactly when the ordering goes wrong: the
	// resolver's container can start before the agent's first pass has raised the
	// interface, fail to bind the gateway, and leave every reserve client without
	// DNS on a node whose dns-filter check is green (it probes the mgmt address,
	// which is always there). Only written on an exit that carries a lifeline.
	NonlocalBindSysctl string
}

// DefaultPaths returns the production-default file locations.
func DefaultPaths() Paths {
	return Paths{
		WGKey:             "/etc/wgfleet/wg.key",
		WGConf:            "/etc/amnezia/amneziawg/awg0.conf",
		NFT:               "/etc/wgfleet/wgfleet.nft",
		WGCF:              "/etc/wireguard/wgcf.conf",
		WARPDir:           "/etc/wgfleet/warp",
		DNS:               "/etc/wgfleet/blocky/config.yml",
		DNSCompose:        "/etc/wgfleet/blocky/docker-compose.yml",
		XrayKey:           "/etc/wgfleet/reality.key",
		XrayConfig:        "/etc/wgfleet/xray/config.json",
		XrayCompose:       "/etc/wgfleet/xray/docker-compose.yml",
		LifelineKey:       "/etc/wgfleet/lifeline.key",
		LifelineConf:      "/etc/amnezia/amneziawg/" + domain.LifelineInterface + ".conf",
		ClientVLESSKey:    "/etc/wgfleet/client-vless.key",
		RoutingState:      "/run/wgfleet/routing.applied",
		ASBlacklist:       "/var/lib/wgfleet/as-blacklist.lst",
		WARPMTUCache:      "/var/lib/wgfleet/warp-mtu",
		WARPEndpointState: "/var/lib/wgfleet/warp-endpoint.json",

		NonlocalBindSysctl: "/etc/sysctl.d/99-wgfleet-nonlocal-bind.conf",
	}
}

// AttemptMarkerPath is the marker a scheduled probe touches on EVERY attempt,
// successful or not, so a failing source backs off to its retry window instead of
// being refetched every pass. It sits next to the probe's cache file.
//
// The pair (cache mtime, marker mtime) is the probe's persisted outcome history:
// the cache advances only on success, the marker on every try. That is what makes
// "attempting regularly but never succeeding" observable from outside the process
// — see metrics.NewProbeCollector. Exported so the planners and the collector
// derive the path the same way.
func AttemptMarkerPath(cachePath string) string { return cachePath + ".attempt" }

// PathsUnder roots every managed file under dir. Useful for non-root or dev runs
// (and tests) where the production /etc layout is not writable.
func PathsUnder(dir string) Paths {
	return Paths{
		WGKey:             filepath.Join(dir, "wg.key"),
		WGConf:            filepath.Join(dir, "awg0.conf"),
		NFT:               filepath.Join(dir, "wgfleet.nft"),
		WGCF:              filepath.Join(dir, "wgcf.conf"),
		WARPDir:           filepath.Join(dir, "warp"),
		DNS:               filepath.Join(dir, "blocky", "config.yml"),
		DNSCompose:        filepath.Join(dir, "blocky", "docker-compose.yml"),
		XrayKey:           filepath.Join(dir, "reality.key"),
		XrayConfig:        filepath.Join(dir, "xray", "config.json"),
		XrayCompose:       filepath.Join(dir, "xray", "docker-compose.yml"),
		LifelineKey:       filepath.Join(dir, "lifeline.key"),
		LifelineConf:      filepath.Join(dir, domain.LifelineInterface+".conf"),
		ClientVLESSKey:    filepath.Join(dir, "client-vless.key"),
		RoutingState:      filepath.Join(dir, "routing.applied"),
		ASBlacklist:       filepath.Join(dir, "as-blacklist.lst"),
		WARPMTUCache:      filepath.Join(dir, "warp-mtu"),
		WARPEndpointState: filepath.Join(dir, "warp-endpoint.json"),

		NonlocalBindSysctl: filepath.Join(dir, "99-wgfleet-nonlocal-bind.conf"),
	}
}
