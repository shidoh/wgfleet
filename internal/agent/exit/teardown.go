package exit

import (
	"context"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/routing"
)

// TeardownPlanners returns the reverse-of-reconcile planners for an exit node:
// bring the AmneziaWG and WARP interfaces down, undo policy routing, remove the
// firewall table, and stop the DNS filter. Run when the node is decommissioned.
// Every step is best-effort (a no-op if it was already torn down) so one failing
// step never blocks the rest.
func TeardownPlanners(p Paths) []reconcile.Planner {
	return []reconcile.Planner{exitTeardownPlanner{paths: p}}
}

type exitTeardownPlanner struct{ paths Paths }

func (exitTeardownPlanner) Component() string { return "exit teardown" }

func (p exitTeardownPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	actions := []reconcile.Action{
		reconcile.BestEffortExecAction("bring AmneziaWG interface down", "awg-quick", "down", p.paths.WGConf),
		reconcile.BestEffortExecAction("bring WARP interface down", "wg-quick", "down", p.paths.WGCF),
	}
	// Undo policy routing (reverse of routing.Render).
	for _, a := range routing.TeardownActions() {
		actions = append(actions, reconcile.BestEffortExecAction(a.Summary, a.Argv...))
	}
	actions = append(actions,
		reconcile.BestEffortExecAction("remove nftables table", "nft", "delete", "table", "inet", "wgfleet"),
		reconcile.BestEffortExecAction("stop DNS filter", "docker", "compose", "-f", p.paths.DNSCompose, "down"),
		reconcile.BestEffortExecAction("stop reality inbound", "docker", "compose", "-f", p.paths.XrayCompose, "down"),
	)

	// Wipe the rendered config and key material once the services are down. On
	// decommission the node's identity is destroyed too (the WG private key), so a
	// re-provision starts clean rather than reusing stale keys/configs.
	wipe := []struct{ path, what string }{
		{p.paths.WGConf, "AmneziaWG interface config"},
		{p.paths.WGCF, "wgcf (WARP) config"},
		{p.paths.NFT, "nftables ruleset"},
		{p.paths.DNS, "blocky config"},
		{p.paths.DNSCompose, "blocky compose file"},
		{p.paths.XrayConfig, "xray (reality) config"},
		{p.paths.XrayCompose, "xray compose file"},
		{p.paths.XrayKey, "REALITY private key"},
		{p.paths.RoutingState, "policy-routing state"},
		{p.paths.ASBlacklist, "AS-blacklist feed cache"},
		{p.paths.ASBlacklist + ".attempt", "AS-blacklist refresh marker"},
		{p.paths.WGKey, "WG private key"},
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
