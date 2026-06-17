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
	FirewallNFT    string // master input-firewall ruleset (inet wgfleet)
	ExtraFilesDir  string // base dir for operator extra files with relative paths
	WGEasyDB       string // wg-easy SQLite db (client-facing AWG server)
	Compose        string // docker-compose.yml for the container stack
	WGEasyAdmin    string // wg-easy admin password file (agent-local, 0600; never crosses the wire)
}

// DefaultPaths returns the production-default file locations.
func DefaultPaths() Paths {
	return Paths{
		MihomoConfig:   "/etc/mihomo/config.yaml",
		DirectNetworks: "/etc/mihomo/direct-networks.yaml",
		NFT:            "/etc/wgfleet/wgfleet-master.nft",
		FirewallNFT:    "/etc/wgfleet/wgfleet.nft",
		ExtraFilesDir:  "/etc/mihomo",
		WGEasyDB:       wgeasy.DefaultDBPath,
		Compose:        "/etc/wgfleet/docker-compose.yml",
		WGEasyAdmin:    "/etc/wgfleet/wg-easy-admin-password",
	}
}

// PathsUnder roots every managed file under dir (non-root/dev runs and tests).
func PathsUnder(dir string) Paths {
	return Paths{
		MihomoConfig:   filepath.Join(dir, "config.yaml"),
		DirectNetworks: filepath.Join(dir, "direct-networks.yaml"),
		NFT:            filepath.Join(dir, "wgfleet-master.nft"),
		FirewallNFT:    filepath.Join(dir, "wgfleet.nft"),
		ExtraFilesDir:  dir,
		WGEasyDB:       filepath.Join(dir, "wg-easy.db"),
		Compose:        filepath.Join(dir, "docker-compose.yml"),
		WGEasyAdmin:    filepath.Join(dir, "wg-easy-admin-password"),
	}
}
