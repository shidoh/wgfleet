package exit

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

const pinnedMaster = "203.0.113.1:48310"

// writeCurrentConfig renders spec into the planner's path, as a previous pass
// would have, so the next Plan sees it as the live config.
func writeCurrentConfig(t *testing.T, pl wgPlanner, spec domain.NodeSpec) {
	t.Helper()
	cfg, err := wg.RenderInterface(wg.RenderInput{Spec: spec.WGServer, Peers: spec.Peers, PrivateKey: pl.privateKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pl.path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func displays(actions []reconcile.Action) []string {
	var out []string
	for _, a := range actions {
		if a.Changes() {
			out = append(out, a.Display)
		}
	}
	return out
}

func hasDisplay(actions []reconcile.Action, frag string) bool {
	for _, d := range displays(actions) {
		if strings.Contains(d, frag) {
			return true
		}
	}
	return false
}

// Turning exit_initiated on must not bounce awg0: `awg-quick down/up` drops the
// tunnel the master is carrying traffic on. Only the endpoint moved, so only the
// endpoint is set.
func TestWGPlannerSetsANewMasterEndpointWithoutRestart(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)
	pl := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true },
		endpoints: func(string) (map[string]string, bool) { return map[string]string{}, true }}
	writeCurrentConfig(t, pl, spec)

	spec.Peers[0].Endpoint = pinnedMaster
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if hasDisplay(actions, "awg-quick") {
		t.Fatalf("endpoint-only change restarted the interface: %v", displays(actions))
	}
	want := "awg set awg0 peer " + spec.Peers[0].PublicKey + " endpoint " + pinnedMaster
	if !hasDisplay(actions, want) {
		t.Fatalf("want %q among %v", want, displays(actions))
	}
}

// Anything besides the endpoint still takes the full path: `awg set` cannot
// change interface-level AmneziaWG parameters or add peers safely.
func TestWGPlannerStillRestartsForOtherChanges(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)
	pl := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true },
		endpoints: func(string) (map[string]string, bool) { return map[string]string{}, true }}
	writeCurrentConfig(t, pl, spec)

	spec.Peers[0].Endpoint = pinnedMaster
	spec.WGServer.MTU = 1380
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDisplay(actions, "awg-quick up") {
		t.Fatalf("an MTU change must re-apply the interface, got %v", displays(actions))
	}
}

// WireGuard roams: one packet from the master off the pinned port and the
// kernel follows it, and every keepalive after that misses the master's gate.
// The planner puts the endpoint back.
func TestWGPlannerRestoresARoamedMasterEndpoint(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)
	spec.Peers[0].Endpoint = pinnedMaster
	live := map[string]string{}
	pl := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true },
		endpoints: func(string) (map[string]string, bool) { return live, true }}
	writeCurrentConfig(t, pl, spec)

	live[spec.Peers[0].PublicKey] = "203.0.113.1:51514"
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDisplay(actions, "endpoint "+pinnedMaster) {
		t.Fatalf("roamed endpoint not restored, got %v", displays(actions))
	}

	live[spec.Peers[0].PublicKey] = pinnedMaster
	actions, err = pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := displays(actions); len(got) != 0 {
		t.Fatalf("endpoint in place: want no changes, got %v", got)
	}
}

// A peer the controller left without an endpoint is the master-dials case, and
// its endpoint is whatever the master last sent from; the watchdog must not touch it.
func TestWGPlannerLeavesPeersWithoutASpecEndpointAlone(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)
	pl := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true },
		endpoints: func(string) (map[string]string, bool) {
			return map[string]string{spec.Peers[0].PublicKey: "203.0.113.1:51514"}, true
		}}
	writeCurrentConfig(t, pl, spec)
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := displays(actions); len(got) != 0 {
		t.Fatalf("want no changes for a master-dials peer, got %v", got)
	}
}

// The controller arms the master's gate on this value, so it must be what the
// KERNEL holds for the peer given an endpoint — not what the spec asked for.
func TestReportedMasterEndpoint(t *testing.T) {
	peers := []domain.PeerSpec{
		{PublicKey: "legacy=", Endpoint: ""},
		{PublicKey: "pertunnel=", Endpoint: pinnedMaster},
	}
	cases := map[string]struct {
		live map[string]string
		want string
	}{
		"kernel holds the pinned endpoint": {map[string]string{"pertunnel=": pinnedMaster}, pinnedMaster},
		"kernel roamed elsewhere":          {map[string]string{"pertunnel=": "203.0.113.1:51514"}, "203.0.113.1:51514"},
		"kernel has none yet":              {map[string]string{}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := reportedMasterEndpoint(peers, tc.live); got != tc.want {
				t.Fatalf("reportedMasterEndpoint = %q, want %q", got, tc.want)
			}
		})
	}
	if got := reportedMasterEndpoint([]domain.PeerSpec{{PublicKey: "legacy="}}, map[string]string{"legacy=": pinnedMaster}); got != "" {
		t.Fatalf("no peer with a spec endpoint: want empty, got %q", got)
	}
}
