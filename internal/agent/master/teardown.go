package master

import (
	"context"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// TeardownPlanners returns the reverse-of-reconcile planners for a master node:
// bring the container stack down and remove the master NAT table. Run when the
// node is decommissioned.
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
	}

	// Wipe the rendered config and the wg-easy DB once the stack is down: on
	// decommission the master is gone, so its client-AWG database (keys included)
	// and mihomo/NAT configs should not linger for a re-provision to reuse.
	wipe := []struct{ path, what string }{
		{p.paths.MihomoConfig, "mihomo config"},
		{p.paths.DirectNetworks, "direct-networks include"},
		{p.paths.NFT, "master NAT ruleset"},
		{p.paths.Compose, "container compose file"},
		{p.paths.WGEasyDB, "wg-easy client database"},
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
