package exit

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func TestMasterPeersReportsEveryPeerOfTheSpec(t *testing.T) {
	peers := []domain.PeerSpec{
		{Name: "master-xa-1", PublicKey: "keyA", Endpoint: "203.0.113.1:23456", AllowedIPs: []string{"10.81.0.2/32"}},
		{Name: "master-xa-2", PublicKey: "keyB", AllowedIPs: []string{"10.81.0.4/32"}},
	}
	read := func(string) ([]wg.DumpPeer, bool) {
		return []wg.DumpPeer{
			{PublicKey: "keyA", Endpoint: "203.0.113.1:23456", LatestHandshake: time.Unix(1_800_000_000, 0)},
			{PublicKey: "keyB", Endpoint: "203.0.113.2:40001"},
			{PublicKey: "stranger", Endpoint: "192.0.2.9:1"},
		}, true
	}
	got, ok := masterPeersFrom(peers, read, "awg0")
	if !ok || len(got) != 2 {
		t.Fatalf("got %+v, %v; want the two peers of the spec and nothing else", got, ok)
	}
	if got[0].PublicKey != "keyA" || got[0].Endpoint != "203.0.113.1:23456" || got[0].LastHandshake.IsZero() {
		t.Errorf("first peer = %+v", got[0])
	}
	if got[1].PublicKey != "keyB" || got[1].Endpoint != "203.0.113.2:40001" || !got[1].LastHandshake.IsZero() {
		t.Errorf("second peer = %+v", got[1])
	}
}

// A spec peer the kernel does not hold is still reported — with nothing in it.
// "The exit has no such peer" is what the controller needs to hear.
func TestMasterPeersReportsASpecPeerMissingFromTheKernel(t *testing.T) {
	peers := []domain.PeerSpec{{PublicKey: "keyA", AllowedIPs: []string{"10.81.0.2/32"}}}
	read := func(string) ([]wg.DumpPeer, bool) { return nil, true }
	got, ok := masterPeersFrom(peers, read, "awg0")
	if !ok || len(got) != 1 || got[0].PublicKey != "keyA" || got[0].Endpoint != "" {
		t.Errorf("got %+v, %v", got, ok)
	}
}

func TestMasterPeersSaysWhenItCannotRead(t *testing.T) {
	peers := []domain.PeerSpec{{PublicKey: "keyA", AllowedIPs: []string{"10.81.0.2/32"}}}
	read := func(string) ([]wg.DumpPeer, bool) { return nil, false }
	if got, ok := masterPeersFrom(peers, read, "awg0"); ok || got != nil {
		t.Errorf("unreadable interface: got %+v, %v; want nil, false", got, ok)
	}
}

// planFor builds the planner over a config the previous pass already wrote, with
// the kernel holding live.
func planFor(t *testing.T, spec domain.NodeSpec, priv string, prev domain.NodeSpec, live []wg.DumpPeer, readable bool) []reconcile.Action {
	t.Helper()
	paths := testPaths(t)
	pl := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true },
		dump: func(string) ([]wg.DumpPeer, bool) { return live, readable }}
	writeCurrentConfig(t, pl, prev)
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return actions
}

func liveOf(peers ...domain.PeerSpec) []wg.DumpPeer {
	out := make([]wg.DumpPeer, 0, len(peers))
	for _, p := range peers {
		ips := append([]string(nil), p.AllowedIPs...)
		sort.Strings(ips)
		out = append(out, wg.DumpPeer{PublicKey: p.PublicKey, AllowedIPs: ips, Keepalive: p.Keepalive, Endpoint: p.Endpoint})
	}
	return out
}

func secondMaster(t *testing.T) domain.PeerSpec {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return domain.PeerSpec{Name: "master-xa-2", PublicKey: kp.PublicKey, AllowedIPs: []string{"10.81.0.4/32"}, Keepalive: 23}
}

// Adding a master on a live fleet adds a peer to every exit at once. A down/up
// there would drop the other master's tunnel on every exit inside one reconcile
// interval — the whole fleet's data plane, for a change that touches none of it.
func TestWGPlannerAddsAMasterPeerWithoutRestart(t *testing.T) {
	prev, priv := exitSpec(t)
	spec := prev
	b := secondMaster(t)
	spec.Peers = append(append([]domain.PeerSpec(nil), prev.Peers...), b)
	actions := planFor(t, spec, priv, prev, liveOf(prev.Peers...), true)
	if hasDisplay(actions, "awg-quick") {
		t.Fatalf("a new master peer restarted the interface: %q", displays(actions))
	}
	want := "awg set awg0 peer " + b.PublicKey + " allowed-ips 10.81.0.4/32 persistent-keepalive 23"
	if !hasDisplay(actions, want) {
		t.Errorf("actions = %q, want %q among them", displays(actions), want)
	}
	if hasDisplay(actions, "peer "+prev.Peers[0].PublicKey) {
		t.Errorf("the peer that did not change was touched: %q", displays(actions))
	}
}

func TestWGPlannerRemovesADepartedMasterPeerWithoutRestart(t *testing.T) {
	spec, priv := exitSpec(t)
	b := secondMaster(t)
	prev := spec
	prev.Peers = append(append([]domain.PeerSpec(nil), spec.Peers...), b)
	actions := planFor(t, spec, priv, prev, liveOf(prev.Peers...), true)
	if !hasDisplay(actions, "awg set awg0 peer "+b.PublicKey+" remove") {
		t.Errorf("actions = %q, want the departed peer removed", displays(actions))
	}
	if hasDisplay(actions, "awg-quick") {
		t.Fatalf("removing a master peer restarted the interface: %q", displays(actions))
	}
}

// The config file already matches the spec — a previous pass wrote it and then
// one `awg set` failed, or someone removed the peer by hand. Comparing files
// would call this converged for ever; the kernel says otherwise.
func TestWGPlannerRepairsAPeerMissingFromTheKernel(t *testing.T) {
	spec, priv := exitSpec(t)
	b := secondMaster(t)
	spec.Peers = append(spec.Peers, b)
	actions := planFor(t, spec, priv, spec, liveOf(spec.Peers[0]), true)
	want := "awg set awg0 peer " + b.PublicKey + " allowed-ips 10.81.0.4/32 persistent-keepalive 23"
	if !hasDisplay(actions, want) {
		t.Errorf("actions = %q, want the missing peer restored by %q", displays(actions), want)
	}
	if hasDisplay(actions, "awg-quick") {
		t.Fatalf("repairing one peer restarted the interface: %q", displays(actions))
	}
}

// A peer present but with the wrong allowed-ips — another peer was given its /32
// and the command that should have moved this one never ran. It handshakes and
// carries nothing.
func TestWGPlannerRepairsAPeerWhoseAllowedIPsWereStolen(t *testing.T) {
	spec, priv := exitSpec(t)
	b := secondMaster(t)
	spec.Peers = append(spec.Peers, b)
	live := liveOf(spec.Peers...)
	live[1].AllowedIPs = nil
	actions := planFor(t, spec, priv, spec, live, true)
	if !hasDisplay(actions, "peer "+b.PublicKey+" allowed-ips 10.81.0.4/32") {
		t.Errorf("actions = %q, want the peer's allowed-ips restated", displays(actions))
	}
}

func TestWGPlannerTurnsKeepaliveOff(t *testing.T) {
	spec, priv := exitSpec(t)
	live := liveOf(spec.Peers...)
	spec.Peers = append([]domain.PeerSpec(nil), spec.Peers...)
	spec.Peers[0].Keepalive = 0
	prev := spec
	actions := planFor(t, spec, priv, prev, live, true)
	if !hasDisplay(actions, "persistent-keepalive off") {
		t.Errorf("actions = %q, want the keepalive switched off, not left at 25", displays(actions))
	}
}

// Nothing in common between the kernel and the spec, on an interface that has
// peers: that is not ours to empty one `remove` at a time. Rebuild it.
func TestWGPlannerRebuildsAnEntirelyForeignPeerList(t *testing.T) {
	spec, priv := exitSpec(t)
	stranger := secondMaster(t)
	actions := planFor(t, spec, priv, spec, liveOf(stranger), true)
	if !hasDisplay(actions, "awg-quick up") {
		t.Errorf("actions = %q, want a restart", displays(actions))
	}
	if hasDisplay(actions, "remove") {
		t.Errorf("a foreign peer was removed in place: %q", displays(actions))
	}
}

func TestWGPlannerConvergedIsQuiet(t *testing.T) {
	spec, priv := exitSpec(t)
	if d := displays(planFor(t, spec, priv, spec, liveOf(spec.Peers...), true)); len(d) != 0 {
		t.Errorf("a converged interface produced actions: %q", d)
	}
}

// With the kernel unreadable there is no telling what an edit would leave behind:
// a changed config falls back to the restart that is known to converge, and an
// unchanged one is left alone.
func TestWGPlannerWithAnUnreadableKernel(t *testing.T) {
	prev, priv := exitSpec(t)
	spec := prev
	spec.Peers = append(append([]domain.PeerSpec(nil), prev.Peers...), secondMaster(t))
	if !hasDisplay(planFor(t, spec, priv, prev, nil, false), "awg-quick up") {
		t.Error("a changed config with an unreadable kernel must restart")
	}
	if d := displays(planFor(t, prev, priv, prev, nil, false)); len(d) != 0 {
		t.Errorf("an unchanged config with an unreadable kernel produced actions: %q", d)
	}
}
