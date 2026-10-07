package keybroker

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// cloneMasterKeys gives master-xa-2 the keys of master-xa-1, straight into the
// store: a master built from a copy of another's disk, registered before the
// controller refused such a key (or by a build that never did).
func cloneMasterKeys(t *testing.T, s seededFleet) {
	t.Helper()
	ctx := context.Background()
	if err := s.st.SetNodePublicKey(ctx, "master-xa-2", s.sharedPubs["master-xa-1"]); err != nil {
		t.Fatal(err)
	}
	if err := s.st.SetNodeTunnelKey(ctx, "master-xa-2", "exit-de-1", s.tunnelPubs["master-xa-1"]); err != nil {
		t.Fatal(err)
	}
}

// The exit's kernel knows a peer by its public key. Two peers with one key on two
// addresses are one peer whose allowed-ips the agent rewrites back and forth, and
// the healthy master loses its return path every other pass. The first master in
// the manifest keeps the key; the later one is not peered and gets no AWG tunnel.
func TestTwoMastersWithOneKeyDoNotShareAnExit(t *testing.T) {
	for _, phase := range []domain.PerTunnelKeyPhase{
		domain.PerTunnelKeyOff, domain.PerTunnelKeyDual, domain.PerTunnelKeySwitch, domain.PerTunnelKeyOn,
	} {
		t.Run(string(phase), func(t *testing.T) {
			fleet := twoMasterFleet()
			fleet.Exits[0].PerTunnelKey = string(phase)
			s := seedTwoMasters(t, fleet)
			var logs bytes.Buffer
			s.b.log = slog.New(slog.NewTextHandler(&logs, nil))

			// What the exit and the base master render with master-xa-2 absent from
			// the manifest altogether, over the same store.
			one := fleet
			one.Masters = fleet.Masters[:1]
			alone := New(s.st, one, slog.New(slog.NewTextHandler(io.Discard, nil)))
			wantPeers := mustRender(t, alone, "exit-de-1").Peers
			wantTunnels := mustRender(t, alone, "master-xa-1").Master.ExitTunnels

			cloneMasterKeys(t, s)

			exitSpec := mustRender(t, s.b, "exit-de-1")
			if !reflect.DeepEqual(exitSpec.Peers, wantPeers) {
				t.Errorf("exit peers = %+v\nwant the base master's alone: %+v", exitSpec.Peers, wantPeers)
			}
			seen := map[string]bool{}
			for _, p := range exitSpec.Peers {
				if seen[p.PublicKey] {
					t.Errorf("public key %s is rendered on two peers", p.PublicKey)
				}
				seen[p.PublicKey] = true
			}
			if got := mustRender(t, s.b, "master-xa-1").Master.ExitTunnels; !reflect.DeepEqual(got, wantTunnels) {
				t.Errorf("base master tunnels = %+v\nwant them as with one master: %+v", got, wantTunnels)
			}
			wantNoTunnel(t, s.b, "master-xa-2")
			// REALITY needs no peer on the exit, so the master is not cut off from it.
			if _, ok := tunnelByName(mustRender(t, s.b, "master-xa-2").Master.ExitTunnels, "exit-de-1-reality"); !ok {
				t.Error("master-xa-2 lost its REALITY tunnel to the exit over a WireGuard key")
			}

			out := logs.String()
			if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "two masters present the same WireGuard key") ||
				!strings.Contains(out, "master-xa-1") || !strings.Contains(out, "master-xa-2") || !strings.Contains(out, "exit-de-1") {
				t.Errorf("no error naming the exit and both masters in the log:\n%s", out)
			}
			// A standing condition is announced once, not on every render.
			mustRender(t, s.b, "exit-de-1")
			mustRender(t, s.b, "master-xa-2")
			if n := strings.Count(logs.String(), "level=ERROR"); n != strings.Count(out, "level=ERROR") {
				t.Errorf("the duplicate key was logged again on a later render (%d error lines)", n)
			}
		})
	}
}

// Guard: distinct keys are untouched — both masters keep their peers and tunnels.
func TestDistinctMasterKeysAreAllPeered(t *testing.T) {
	fleet := twoMasterFleet()
	fleet.Exits[0].PerTunnelKey = string(domain.PerTunnelKeyDual)
	s := seedTwoMasters(t, fleet)
	if got := len(mustRender(t, s.b, "exit-de-1").Peers); got != 4 {
		t.Errorf("exit peers = %d, want 4 (two per master in dual)", got)
	}
	for _, m := range []string{"master-xa-1", "master-xa-2"} {
		if _, ok := tunnelByName(mustRender(t, s.b, m).Master.ExitTunnels, "exit-de-1"); !ok {
			t.Errorf("%s has no AWG tunnel", m)
		}
	}
}

// The registry refuses the key at the door: a second master publishing a key
// another manifest master already holds is told so, instead of being stored and
// then silently left without a peer.
func TestRegisteringAnotherMastersKeyIsRefused(t *testing.T) {
	ctx := context.Background()
	s := seedTwoMasters(t, twoMasterFleet())
	keyA, tunnelA := s.sharedPubs["master-xa-1"], s.tunnelPubs["master-xa-1"]

	if err := s.b.RegisterPublicKey(ctx, "master-xa-2", keyA); err == nil {
		t.Error("master-xa-2 registered master-xa-1's shared key")
	} else if !strings.Contains(err.Error(), "master-xa-1") {
		t.Errorf("err = %v, want it to name the master that holds the key", err)
	}
	if err := s.b.RegisterTunnelKey(ctx, "master-xa-2", "exit-de-1", tunnelA); err == nil {
		t.Error("master-xa-2 registered master-xa-1's per-tunnel key for the same exit")
	} else if !strings.Contains(err.Error(), "master-xa-1") {
		t.Errorf("err = %v, want it to name the master that holds the key", err)
	}
	// Nothing was stored.
	node, err := s.st.GetNode(ctx, "master-xa-2")
	if err != nil {
		t.Fatal(err)
	}
	if node.PublicKey != s.sharedPubs["master-xa-2"] {
		t.Errorf("stored shared key = %q, want master-xa-2's own left in place", node.PublicKey)
	}
	keys, err := s.st.ListNodeTunnelKeys(ctx, "master-xa-2")
	if err != nil {
		t.Fatal(err)
	}
	if keys["exit-de-1"] != s.tunnelPubs["master-xa-2"] {
		t.Errorf("stored per-tunnel key = %q, want master-xa-2's own left in place", keys["exit-de-1"])
	}

	// A node's own unchanged key is republished every pass and stays a no-op, and
	// so does a real rotation to a key nobody holds.
	if err := s.b.RegisterPublicKey(ctx, "master-xa-1", keyA); err != nil {
		t.Errorf("re-registering an own unchanged key: %v", err)
	}
	if err := s.b.RegisterTunnelKey(ctx, "master-xa-1", "exit-de-1", tunnelA); err != nil {
		t.Errorf("re-registering an own unchanged per-tunnel key: %v", err)
	}
	if err := s.b.RegisterPublicKey(ctx, "master-xa-2", wgKeyA); err != nil {
		t.Errorf("rotating to a fresh key: %v", err)
	}
	if err := s.b.RegisterTunnelKey(ctx, "master-xa-2", "exit-de-1", wgKeyB); err != nil {
		t.Errorf("rotating to a fresh per-tunnel key: %v", err)
	}
}
