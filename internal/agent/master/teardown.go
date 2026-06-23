package master

import (
	"context"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// TeardownPlanners returns the reverse-of-reconcile planners for a master node:
// bring the container stack down and remove the master NAT + input-firewall tables.
// Run when the node is decommissioned.
func TeardownPlanners(p Paths) []reconcile.Planner {
	return []reconcile.Planner{
		masterTeardownPlanner{paths: p},
	}
}

type masterTeardownPlanner struct{ paths Paths }

func (masterTeardownPlanner) Component() string { return "master teardown" }

func (p masterTeardownPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	actions := []reconcile.Action{
		reconcile.BestEffortExecAction("bring the container stack down",
			"docker", "compose", "-f", p.paths.Compose, "down"),
		reconcile.BestEffortExecAction("remove master NAT table",
			"nft", "delete", "table", "ip", "wgfleet_master"),
		reconcile.BestEffortExecAction("remove master input-firewall table",
			"nft", "delete", "table", "inet", "wgfleet"),
	}
	// Master-tier blocky runs as its own compose project (ADR-0024); bring it down too.
	if p.paths.DNSCompose != "" {
		actions = append(actions, reconcile.BestEffortExecAction("bring the blocky resolver down",
			"docker", "compose", "-f", p.paths.DNSCompose, "down"))
	}

	// Wipe the rendered config and the wg-easy DB once the stack is down: on
	// decommission the master is gone, so its client-AWG database (keys included)
	// and mihomo/NAT configs should not linger for a re-provision to reuse.
	wipe := []struct{ path, what string }{
		{p.paths.MihomoConfig, "mihomo config"},
		{p.paths.DirectNetworks, "direct-networks include"},
		{p.paths.NFT, "master NAT ruleset"},
		{p.paths.FirewallNFT, "master input-firewall ruleset"},
		{p.paths.Compose, "container compose file"},
		{p.paths.WGEasyDB, "wg-easy client database"},
		{p.paths.DNS, "blocky resolver config"},
		{p.paths.DNSCompose, "blocky compose file"},
	}
	for _, w := range wipe {
		if w.path == "" {
			continue
		}
		rm, err := reconcile.RemoveFileAction(w.path, "wipe "+w.what)
		if err != nil {
			return nil, err
		}
		actions = append(actions, rm)
	}
	return actions, nil
}
