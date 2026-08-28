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
		// The client-facing interface first: it is the one carrying end users, and
		// on a master that owns it (rather than wg-easy) nothing else takes it down.
		// Best-effort — an unmanaged master has no such config and this is a no-op.
		reconcile.BestEffortExecAction("bring the client interface down",
			"awg-quick", "down", p.paths.ClientWGConf),
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
	// Client-facing VLESS inbound (xray) runs as its own compose project (ADR-0031);
	// bring it down too. Otherwise decommission leaves the container serving valid
	// client credentials with the REALITY private key long after teardown "completes".
	if p.paths.ClientVLESSYML != "" {
		actions = append(actions, reconcile.BestEffortExecAction("bring the client vless inbound down",
			"docker", "compose", "-f", p.paths.ClientVLESSYML, "down"))
	}

	// Wipe the rendered config and the wg-easy DB once the stack is down: on
	// decommission the master is gone, so its client-AWG database (keys included)
	// and mihomo/NAT configs should not linger for a re-provision to reuse.
	wipe := []struct{ path, what string }{
		{p.paths.MihomoConfig, "mihomo config"},
		{p.paths.DirectNetworks, "direct-networks include"},
		{p.paths.NFT, "master NAT ruleset"},
		{p.paths.V6NFT, "master client-facing IPv6 ruleset"},
		{p.paths.FirewallNFT, "master input-firewall ruleset"},
		{p.paths.Compose, "container compose file"},
		{p.paths.WGEasyDB, "wg-easy client database"},
		{p.paths.DNS, "blocky resolver config"},
		{p.paths.DNSCompose, "blocky compose file"},
		// client-vless config.json holds the REALITY private key AND every issued
		// client UUID; the key file is the master's client-facing REALITY private key.
		// Both must be destroyed with the node's identity (ADR-0031).
		{p.paths.ClientVLESS, "client vless config (REALITY key + client UUIDs)"},
		{p.paths.ClientVLESSYML, "client vless compose file"},
		{p.paths.ClientVLESSKey, "client vless REALITY private key"},
		// The client interface config holds the master's client-facing private key
		// AND every issued client's preshared key; the key file holds that same
		// identity. Both must die with the node for the same reason the vless key
		// above does — a decommissioned VPS goes back to its provider.
		{p.paths.ClientWGConf, "client interface config (interface key + client preshared keys)"},
		{p.paths.ClientWGKey, "client-facing WireGuard private key"},
		{ClaimPathFor(p.paths.ClientWGConf), "client interface claim"},
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
