package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Decommission means the node's identity is destroyed with it. The client leg is
// the one that carries end users, so leaving it up on a retired master keeps
// serving them, and leaving its files behind leaves the interface private key
// AND every client's preshared key on a VPS that goes back to the provider.
//
// Before the agent owned this interface, `docker compose down` took it with the
// container; owning it means owning its teardown too.
func TestMasterTeardownRetiresTheClientInterface(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	planners := TeardownPlanners(paths)

	var summaries, targets []string
	for _, p := range planners {
		actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		for _, a := range actions {
			summaries = append(summaries, a.Summary)
			targets = append(targets, a.Target)
		}
	}
	all := strings.Join(summaries, "\n")
	if !strings.Contains(all, "client interface down") {
		t.Errorf("teardown leaves the client interface up:\n%s", all)
	}

	joined := strings.Join(targets, "\n")
	for _, secret := range []string{paths.ClientWGConf, paths.ClientWGKey} {
		if !strings.Contains(joined, secret) {
			t.Errorf("teardown leaves %s on disk — it holds the interface key and every client's preshared key", secret)
		}
	}
}

// The client-VLESS secrets (ADR-0031) must still be wiped: these assertions were
// guarding that before this branch and were lost when the file was rewritten.
func TestMasterTeardownWipesEveryNodeSecret(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	var targets, summaries []string
	for _, p := range TeardownPlanners(paths) {
		actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		for _, a := range actions {
			targets = append(targets, a.Target)
			summaries = append(summaries, a.Summary)
		}
	}
	joined := strings.Join(targets, "\n")
	for _, secret := range []string{
		paths.ClientVLESS,    // REALITY private key + every issued client UUID
		paths.ClientVLESSKey, // the master's client-facing REALITY key
		paths.WGEasyDB,       // wg-easy's client database, keys included
		paths.ClientWGConf,   // interface key + every client preshared key
		paths.ClientWGKey,
		ClaimPathFor(paths.ClientWGConf),
	} {
		if !strings.Contains(joined, secret) {
			t.Errorf("teardown leaves %s on a decommissioned host", secret)
		}
	}
	// And the node's tables go with it.
	all := strings.Join(summaries, "\n")
	for _, want := range []string{"master NAT table", "input-firewall table", "container stack down"} {
		if !strings.Contains(all, want) {
			t.Errorf("teardown no longer removes %q", want)
		}
	}
}

// Teardown reversed the two IPv4 tables and nothing else it had created. What it
// left behind was not untidy, it was dangerous: an ip6 table whose forward hook is
// `policy drop`, `net.ipv6.conf.all.forwarding=1` with nothing gating it, and an
// `ip rule fwmark 0x2` pointing at a route table full of local-delivery routes. A
// decommissioned host later repurposed as an exit then drops every forwarded IPv6
// packet, with no rendered file anywhere on the box to explain why.
func TestMasterTeardownReversesEverythingItInstalled(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	var summaries, targets []string
	for _, pl := range TeardownPlanners(paths) {
		acts, err := pl.Plan(context.Background(), domain.NodeSpec{})
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range acts {
			summaries = append(summaries, a.Summary+" "+a.Target+" "+a.Display)
			targets = append(targets, a.Target)
		}
	}
	all := strings.Join(summaries, "\n")
	for _, want := range []string{
		"stop forwarding IPv6",
		"remove the client-facing IPv6 table",
		"remove the TPROXY policy route",
		"flush the TPROXY route table",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("teardown never reverses %q:\n%s", want, all)
		}
	}
	// Forwarding must go down BEFORE the drop policy is deleted, or the host is an
	// open IPv6 router for the seconds in between.
	if i, j := strings.Index(all, "stop forwarding IPv6"), strings.Index(all, "remove the client-facing IPv6 table"); i > j {
		t.Error("the IPv6 table is deleted before forwarding is lowered: an open router in between")
	}
	// And every ruleset's applied-marker goes with it, or a re-provision that renders
	// identical bytes finds a marker that matches and never runs nft at all.
	for _, path := range []string{paths.NFT, paths.V6NFT, paths.FirewallNFT} {
		marker := reconcile.NFTAppliedMarker(path)
		found := false
		for _, tgt := range targets {
			if tgt == marker {
				found = true
			}
		}
		if !found {
			t.Errorf("teardown leaves the applied-marker %s behind", marker)
		}
	}
}

// Decommission must leave nothing of the namespaces behind.
//
// The routing rule and its table outlive both nft tables — a stray
// `iif wg0 lookup 51822` on a repurposed host sends client traffic to a route
// that means nothing there — and the prober is a real peer with a real private
// key on the client interface, so it dies with the node exactly as an end user's
// credential does.
func TestTeardownRemovesBothNamespacesAndTheProber(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	acts, err := TeardownPlanners(paths)[0].Plan(context.Background(), domain.NodeSpec{
		Role: domain.RoleMaster, Master: &domain.MasterSpec{},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + " | " + a.Target + "\n"
	}
	for _, want := range []string{
		"ip rule del pref 400",
		"ip route flush table 51822",
		"ip link del mih-host",
		"ip netns del wgfleet-synth",
		"client-wg-synth.key",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("teardown leaves %q behind:\n%s", want, dump)
		}
	}
}
