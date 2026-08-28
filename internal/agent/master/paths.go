// Package master assembles the master-role reconcilers into a plan the engine
// can run in dry-run or apply mode. The master's data plane is mihomo (proxy
// router + load balancer over the exit tunnels) plus the NAT rules that DNAT
// client traffic into mihomo and masquerade it outbound. Each planner wraps a
// pure renderer (internal/mihomo, internal/netfw) as a reconcile.Planner, so the
// whole master converges from one NodeSpec and every step is dry-run visible.
package master

import (
	"path/filepath"

	"github.com/shidoh/wgfleet/internal/wgeasy"
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
	WGEasyDB       string // wg-easy SQLite db (client-facing AWG server)
	Compose        string // docker-compose.yml for the container stack
	WGEasyAdmin    string // wg-easy admin password file (agent-local, 0600; never crosses the wire)
	DNS            string // master-tier blocky resolver config (config.yml, ADR-0024)
	DNSCompose     string // docker-compose.yml for the master blocky container
	ClientVLESS    string // client-facing xray inbound config.json (holds the REALITY private key, 0600)
	ClientVLESSYML string // docker-compose.yml for the master client-vless xray container
	ClientVLESSKey string // master's client-facing REALITY x25519 private key (0600); wiped on teardown
	ClientWGConf   string // client-facing AmneziaWG interface config (0600); the interface name comes from this filename
	ClientWGKey    string // master's client-facing WireGuard private key (0600); adopted from wg-easy on handover
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
		WGEasyDB:       wgeasy.DefaultDBPath,
		Compose:        "/etc/wgfleet/docker-compose.yml",
		WGEasyAdmin:    "/etc/wgfleet/wg-easy-admin-password",
		DNS:            "/etc/wgfleet/blocky/config.yml",
		DNSCompose:     "/etc/wgfleet/blocky/docker-compose.yml",
		ClientVLESS:    "/etc/wgfleet/client-vless/config.json",
		ClientVLESSYML: "/etc/wgfleet/client-vless/docker-compose.yml",
		// Mirrors exit.Paths.ClientVLESSKey — the agent generates/reads the master's
		// client-facing REALITY key there (main.go ensureClientVlessKey); teardown
		// wipes the same file so a decommissioned master leaves no key behind.
		ClientVLESSKey: "/etc/wgfleet/client-vless.key",
		// The filename IS the interface name: wg0 keeps the name wg-easy used, so the
		// NAT, MSS-clamp and DOCKER-USER rules that already reference it need no change
		// when the leg changes hands.
		ClientWGConf: "/etc/amnezia/amneziawg/wg0.conf",
		ClientWGKey:  "/etc/wgfleet/client-wg.key",
	}
}

// PathsUnder roots every managed file under dir (non-root/dev runs and tests).
func PathsUnder(dir string) Paths {
	return Paths{
		MihomoConfig:   filepath.Join(dir, "config.yaml"),
		DirectNetworks: filepath.Join(dir, "direct-networks.yaml"),
		NFT:            filepath.Join(dir, "wgfleet-master.nft"),
		V6NFT:          filepath.Join(dir, "wgfleet-master-v6.nft"),
		FirewallNFT:    filepath.Join(dir, "wgfleet.nft"),
		ExtraFilesDir:  dir,
		UIDir:          filepath.Join(dir, "ui"),
		WGEasyDB:       filepath.Join(dir, "wg-easy.db"),
		Compose:        filepath.Join(dir, "docker-compose.yml"),
		WGEasyAdmin:    filepath.Join(dir, "wg-easy-admin-password"),
		DNS:            filepath.Join(dir, "blocky", "config.yml"),
		DNSCompose:     filepath.Join(dir, "blocky", "docker-compose.yml"),
		ClientVLESS:    filepath.Join(dir, "client-vless", "config.json"),
		ClientVLESSYML: filepath.Join(dir, "client-vless", "docker-compose.yml"),
		ClientVLESSKey: filepath.Join(dir, "client-vless.key"),
		ClientWGConf:   filepath.Join(dir, "wg0.conf"),
		ClientWGKey:    filepath.Join(dir, "client-wg.key"),
	}
}
