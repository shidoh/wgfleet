// Package master assembles the master-role reconcilers into a plan the engine
// can run in dry-run or apply mode. The master's data plane is mihomo (proxy
// router + load balancer over the exit tunnels) plus the NAT rules that DNAT
// client traffic into mihomo and masquerade it outbound. Each planner wraps a
// pure renderer (internal/mihomo, internal/netfw) as a reconcile.Planner, so the
// whole master converges from one NodeSpec and every step is dry-run visible.
package master

import (
	"path/filepath"
)

// Paths are the on-node file locations the master reconcilers manage.
type Paths struct {
	MihomoConfig   string // mihomo config.yaml
	DirectNetworks string // included direct-networks.yaml
	NFT            string // master NAT ruleset
	V6NFT          string // master client-facing IPv6 ruleset (ip6 wgfleet_master_v6)
	FirewallNFT    string // master input-firewall ruleset (inet wgfleet)
	ExtraFilesDir  string // base dir for operator extra files with relative paths
	UIDir          string // mihomo external-ui dir; the agent populates it (see dashboardPlanner)
	Compose        string // docker-compose.yml for the container stack
	DNS            string // master-tier blocky resolver config (config.yml, ADR-0024)
	DNSCompose     string // docker-compose.yml for the master blocky container
	ClientVLESS    string // client-facing xray inbound config.json (holds the REALITY private key, 0600)
	ClientVLESSYML string // docker-compose.yml for the master client-vless xray container
	ClientVLESSKey string // master's client-facing REALITY x25519 private key (0600); wiped on teardown
	// RealityPortal is the portal xray config.json (ADR-0038; holds the portal
	// REALITY private key and every bridge UUID, 0600); RealityPortalYML its
	// compose file; RealityPortalKey the portal's REALITY x25519 private key,
	// kept while no exit uses the portal and wiped only on teardown.
	RealityPortal    string
	RealityPortalYML string
	RealityPortalKey string
	ClientWGConf     string // client-facing AmneziaWG interface config (0600); the interface name comes from this filename
	ClientWGKey      string // master's client-facing WireGuard private key (0600)
	// SynthKey is the private key of the master's OWN client — the peer it uses to
	// measure whether a packet entering the client interface comes back. Node-local
	// and never published: nobody has to re-issue this config, so a key that never
	// leaves is one fewer thing to leak.
	SynthKey string
	// NetnsMoveState is where the migration decision records its attempts and its
	// terminal verdict, so a restart does not hand a node that has already been
	// judged unfit a fresh set of three flips.
	NetnsMoveState string
	// SynthConf is the prober's device config, in `awg setconf` form.
	SynthConf string
}

// DefaultPaths returns the production-default file locations.
func DefaultPaths() Paths {
	return Paths{
		MihomoConfig:   "/etc/mihomo/config.yaml",
		DirectNetworks: "/etc/mihomo/direct-networks.yaml",
		NFT:            "/etc/wgfleet/wgfleet-master.nft",
		V6NFT:          "/etc/wgfleet/wgfleet-master-v6.nft",
		FirewallNFT:    "/etc/wgfleet/wgfleet.nft",
		ExtraFilesDir:  "/etc/mihomo",
		UIDir:          "/etc/mihomo/ui",
		Compose:        "/etc/wgfleet/docker-compose.yml",
		DNS:            "/etc/wgfleet/blocky/config.yml",
		DNSCompose:     "/etc/wgfleet/blocky/docker-compose.yml",
		ClientVLESS:    "/etc/wgfleet/client-vless/config.json",
		ClientVLESSYML: "/etc/wgfleet/client-vless/docker-compose.yml",
		// Mirrors exit.Paths.ClientVLESSKey — the agent generates/reads the master's
		// client-facing REALITY key there (main.go ensureClientVlessKey); teardown
		// wipes the same file so a decommissioned master leaves no key behind.
		ClientVLESSKey:   "/etc/wgfleet/client-vless.key",
		RealityPortal:    "/etc/wgfleet/reality-portal/config.json",
		RealityPortalYML: "/etc/wgfleet/reality-portal/docker-compose.yml",
		RealityPortalKey: "/etc/wgfleet/reality-portal.key",
		// The filename IS the interface name (domain.ClientWGInterface).
		ClientWGConf:   "/etc/amnezia/amneziawg/wg0.conf",
		ClientWGKey:    "/etc/wgfleet/client-wg.key",
		SynthKey:       "/etc/wgfleet/client-wg-synth.key",
		NetnsMoveState: "/etc/wgfleet/netns-move.json",
		SynthConf:      "/etc/wgfleet/client-wg-synth.conf",
	}
}

// PathsUnder roots every managed file under dir (non-root/dev runs and tests).
func PathsUnder(dir string) Paths {
	return Paths{
		MihomoConfig:     filepath.Join(dir, "config.yaml"),
		DirectNetworks:   filepath.Join(dir, "direct-networks.yaml"),
		NFT:              filepath.Join(dir, "wgfleet-master.nft"),
		V6NFT:            filepath.Join(dir, "wgfleet-master-v6.nft"),
		FirewallNFT:      filepath.Join(dir, "wgfleet.nft"),
		ExtraFilesDir:    dir,
		UIDir:            filepath.Join(dir, "ui"),
		Compose:          filepath.Join(dir, "docker-compose.yml"),
		DNS:              filepath.Join(dir, "blocky", "config.yml"),
		DNSCompose:       filepath.Join(dir, "blocky", "docker-compose.yml"),
		ClientVLESS:      filepath.Join(dir, "client-vless", "config.json"),
		ClientVLESSYML:   filepath.Join(dir, "client-vless", "docker-compose.yml"),
		ClientVLESSKey:   filepath.Join(dir, "client-vless.key"),
		RealityPortal:    filepath.Join(dir, "reality-portal", "config.json"),
		RealityPortalYML: filepath.Join(dir, "reality-portal", "docker-compose.yml"),
		RealityPortalKey: filepath.Join(dir, "reality-portal.key"),
		ClientWGConf:     filepath.Join(dir, "wg0.conf"),
		ClientWGKey:      filepath.Join(dir, "client-wg.key"),
		SynthKey:         filepath.Join(dir, "client-wg-synth.key"),
		NetnsMoveState:   filepath.Join(dir, "netns-move.json"),
		SynthConf:        filepath.Join(dir, "client-wg-synth.conf"),
	}
}
