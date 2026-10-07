package exit

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/keybroker"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/routing"
	"github.com/shidoh/wgfleet/internal/wg"
)

// crossLayerFleet is the smallest fleet both layers have something to say about:
// one WARP exit and one master, or two. The anchor label and the management
// subnet are declared, as the manifest checks require of a two-master fleet, so
// the second master is the ONLY difference between the two renders.
func crossLayerFleet(masters int) config.FleetSection {
	all := []config.MasterConfig{
		{Name: "master-xa-1", Slot: 0, MgmtAddr: "10.20.25.254", PublicIP: "203.0.113.1",
			ClientAWG: config.ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"},
			Routing:   config.MasterRouting{DirectCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}, Balance: "health"}},
		{Name: "master-xa-2", Slot: 1, MgmtAddr: "10.20.25.253", PublicIP: "203.0.113.2",
			ClientAWG: config.ClientAWGConfig{ListenPort: 443, AddressPool: "10.90.0.0/24"},
			Routing:   config.MasterRouting{DirectCIDRs: []string{"172.16.0.0/12"}, Balance: "health"}},
	}
	return config.FleetSection{
		InterfaceAnchor: "master-xa-1",
		MgmtSubnet:      "10.20.0.0/16",
		Masters:         all[:masters],
		Exits: []config.ExitConfig{{
			Name: "exit-de-1", Region: "de", Egress: "warp", AddressPool: "10.81.0.0/24",
			MgmtAddr: "10.20.25.1", PublicIP: "198.51.100.1",
		}},
	}
}

// The controller renders a second master as one more peer and one more direct
// route; the exit agent has to take exactly that as one `awg set` and one rule.
// Each layer has its own tests for its half. This one feeds the real render of
// the one into the real planners of the other, from an exit that already carries
// the one-master config — the upgrade every exit of a live fleet goes through at
// once when a master is added.
func TestASecondMasterReachesARunningExitInPlace(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys := map[string]wg.KeyPair{}
	for id, role := range map[string]domain.Role{
		"master-xa-1": domain.RoleMaster, "master-xa-2": domain.RoleMaster, "exit-de-1": domain.RoleExit,
	} {
		kp, err := wg.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = kp
		if err := st.UpsertNode(ctx, domain.Node{ID: id, Name: id, Role: role, State: domain.StateReady,
			WireVersion: api.WireContractVersion}); err != nil {
			t.Fatal(err)
		}
		if err := st.SetNodePublicKey(ctx, id, kp.PublicKey); err != nil {
			t.Fatal(err)
		}
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	render := func(masters int) domain.NodeSpec {
		t.Helper()
		spec, err := keybroker.New(st, crossLayerFleet(masters), quiet).RenderNodeSpec(ctx, "exit-de-1")
		if err != nil {
			t.Fatalf("render with %d master(s): %v", masters, err)
		}
		return spec
	}
	one, two := render(1), render(2)
	if len(one.Peers) != 1 || len(two.Peers) != 2 {
		t.Fatalf("peers: %d with one master, %d with two; want 1 and 2", len(one.Peers), len(two.Peers))
	}
	second := two.Peers[1]
	if second.PublicKey != keys["master-xa-2"].PublicKey {
		t.Fatalf("the second peer is not master-xa-2's: %+v", second)
	}

	// The exit as the one-master config left it: file written, interface up, the
	// kernel holding that one peer, the routing intent recorded.
	paths := testPaths(t)
	priv := keys["exit-de-1"].PrivateKey
	wgp := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true },
		dump:      func(string) ([]wg.DumpPeer, bool) { return liveOf(one.Peers...), true },
		endpoints: func(string) (map[string]string, bool) { return nil, true }}
	writeCurrentConfig(t, wgp, one)
	rp := routingPlanner{statePath: paths.RoutingState, applied: func(domain.RoutingSpec) bool { return true }}
	intent := one.Routing
	intent.ClientCIDR = one.WGServer.AddressPool
	steps, err := routing.Render(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.RoutingState, []byte(routing.Script(steps)), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, pl := range map[string]reconcile.Planner{"interface": wgp, "routing": rp} {
		settled, err := pl.Plan(ctx, one)
		if err != nil {
			t.Fatal(err)
		}
		if d := displays(settled); len(d) != 0 {
			t.Fatalf("the fixture is not a converged one-master exit; %s plan: %q", name, d)
		}
	}

	iface, err := wgp.Plan(ctx, two)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDisplay(iface, "awg set awg0 peer "+second.PublicKey+" allowed-ips "+second.AllowedIPs[0]) {
		t.Errorf("interface plan = %q, want an `awg set` for the second master's peer", displays(iface))
	}
	if hasDisplay(iface, "awg-quick") {
		t.Errorf("the second master restarted the interface the first one's traffic is on: %q", displays(iface))
	}
	if hasDisplay(iface, "peer "+one.Peers[0].PublicKey) {
		t.Errorf("the first master's peer was touched: %q", displays(iface))
	}

	routes, err := rp.Plan(ctx, two)
	if err != nil {
		t.Fatal(err)
	}
	if !hasExec(routes, "ip rule add to 203.0.113.2/32 lookup main") {
		t.Errorf("routing plan = %q, want a direct rule for the second master's address", displays(routes))
	}
	if flushesAllConntrack(routes) {
		t.Errorf("the second master flushed all of conntrack on the exit: %q", displays(routes))
	}
}
