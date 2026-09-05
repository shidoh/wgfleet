package master

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netfw"
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
		// The IPv6 refusal, and the sysctl that makes it reachable. Order matters and
		// is the mirror of the ON path: lower forwarding FIRST, because between the two
		// commands a host with the drop policy already deleted but forwarding still on
		// is an open IPv6 router. Leaving either behind is worse than untidy — a
		// decommissioned host later repurposed as an exit silently drops every
		// forwarded IPv6 packet, with no rendered file anywhere on the box to explain
		// why (the ruleset is wiped below, the kernel table is not).
		reconcile.BestEffortExecAction("stop forwarding IPv6",
			"sysctl", "-w", "net.ipv6.conf.all.forwarding=0"),
		reconcile.BestEffortExecAction("remove the client-facing IPv6 table",
			"nft", "delete", "table", "ip6", "wgfleet_master_v6"),
		// TPROXY policy routing. The rule and the table it points at outlive both nft
		// tables, and a stray `fwmark 0x2 lookup 51821` on a repurposed host sends
		// anything carrying that mark to a local-delivery route that no longer means
		// anything here.
		reconcile.BestEffortExecAction("remove the TPROXY policy route",
			"ip", "rule", "del", "fwmark", fmt.Sprintf("%#x", netfw.TProxyMark),
			"lookup", fmt.Sprintf("%d", netfw.TProxyTable)),
		reconcile.BestEffortExecAction("flush the TPROXY route table",
			"ip", "route", "flush", "table", fmt.Sprintf("%d", netfw.TProxyTable)),
		// mihomo's namespace and everything that pointed into it. The rule and the
		// table outlive both nft tables, and a stray `iif wg0 lookup 51822` on a
		// repurposed host sends client traffic to a route that means nothing there.
		reconcile.BestEffortExecAction("remove the namespace routing rule",
			"ip", "rule", "del", "pref", fmt.Sprintf("%d", netfw.NetnsRulePref)),
		reconcile.BestEffortExecAction("flush the namespace route table",
			"ip", "route", "flush", "table", fmt.Sprintf("%d", netfw.NetnsRouteTable)),
		// The destination exemptions that kept the corporate networks, the management
		// overlay and the exits' own addresses out of the namespace. They sit at their
		// own priority and outlive every table here; on a repurposed host they would
		// go on diverting those destinations to a policy nobody set.
		reconcile.BestEffortExecAction("remove the direct-destination exemptions",
			"sh", "-c", fmt.Sprintf("while ip rule del pref %d 2>/dev/null; do :; done", netnsDirectRulePref)),
		reconcile.BestEffortExecAction("remove the veth to mihomo's namespace",
			"ip", "link", "del", domain.NetnsHostIface),
		// The prober's namespace, its interface and its resolver. The interface goes
		// with the namespace; the resolv.conf does not, and a left-behind
		// /etc/netns/<name>/resolv.conf would be picked up by any future namespace of
		// the same name.
		reconcile.BestEffortExecAction("remove the client-path prober's namespace",
			"ip", "netns", "del", synthNetns),
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
		// The prober's identity and its rendered device config. It is a real peer on
		// the client interface with a real key, so it dies with the node exactly as an
		// end user's credential does.
		{p.paths.SynthKey, "client-path prober private key"},
		{p.paths.SynthConf, "client-path prober device config"},
		{synthResolvConf, "client-path prober resolver"},
		{ClaimPathFor(p.paths.ClientWGConf), "client interface claim"},
		// The in-namespace ruleset and its bookkeeping, alongside the host's. Left
		// behind, a re-provision of this host would find an applied marker vouching
		// for a table in a namespace that no longer exists.
		{netnsNFTPath, "in-namespace interception ruleset"},
		{reconcile.NFTAppliedMarker(netnsNFTPath), "in-namespace ruleset applied marker"},
		// The migration's memory: attempts spent and whether this node was judged
		// unfit. It is a verdict about a node that is going away.
		{p.paths.NetnsMoveState, "namespace migration state"},
	}
	// The applied-markers beside each ruleset. Wiping the ruleset and leaving its
	// marker means a re-provision that renders byte-identical bytes finds a marker
	// that already matches and never runs `nft -f` at all — the node comes back with
	// the file on disk and nothing in the kernel.
	for _, path := range []string{p.paths.NFT, p.paths.V6NFT, p.paths.FirewallNFT} {
		if path == "" {
			continue
		}
		wipe = append(wipe, struct{ path, what string }{
			reconcile.NFTAppliedMarker(path), "applied-marker for " + path,
		})
		// The rollback copy goes with it. It is a ruleset for a node that no longer
		// exists in this role, and leaving it behind hands a re-provision — or an
		// operator following the rollback runbook — a firewall from a previous life.
		wipe = append(wipe, struct{ path, what string }{
			reconcile.NFTPreviousRuleset(path), "rollback ruleset for " + path,
		})
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
