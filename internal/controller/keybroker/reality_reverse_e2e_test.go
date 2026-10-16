package keybroker

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// Every master's portal admits exactly what the exit's bridge presents to it,
// at the address and with the key that master published.
func TestRealityReverseBothEndsAgreeAcrossMasters(t *testing.T) {
	s := newReverseSetup(t)
	ctx := context.Background()
	exitSpec, err := s.b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	peers := map[string]domain.RealityPortalPeer{}
	for _, p := range exitSpec.Reality.Bridge.Portals {
		peers[p.Master] = p
	}
	for _, m := range s.b.fleet.Masters {
		spec, err := s.b.RenderNodeSpec(ctx, m.Name)
		if err != nil {
			t.Fatal(err)
		}
		portal := spec.Master.RealityPortal
		peer, ok := peers[m.Name]
		if portal == nil || !ok {
			t.Fatalf("%s: portal %v, bridge peer present %v", m.Name, portal, ok)
		}
		c := portal.Clients[0]
		if c.Exit != "exit-de-1" || c.UUID != peer.UUID || c.ShortID != peer.ShortID || portal.ServerName != peer.ServerName {
			t.Errorf("%s: portal client %+v vs bridge peer %+v", m.Name, c, peer)
		}
		if !strings.HasSuffix(peer.Address, ":"+itoaPort(portal.ListenPort)) || peer.PublicKey != s.pubs[m.Name] {
			t.Errorf("%s: bridge dials %s with %s; portal listens on %d with %s", m.Name, peer.Address, peer.PublicKey, portal.ListenPort, s.pubs[m.Name])
		}
	}
}

// Removing the flag is the rollback: the exit listens on 443 again, opens it, and
// every master dials it forward.
func TestRealityReverseFlagOffRestoresForward(t *testing.T) {
	s := newReverseSetup(t)
	ctx := context.Background()
	_, pub, err := xray.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.SetNodeRealityKey(ctx, "exit-de-1", pub); err != nil {
		t.Fatal(err)
	}
	s.b.fleet.Exits[0].Transports.Reality.ExitInitiated = false
	exitSpec, err := s.b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if r := exitSpec.Reality; r.Bridge != nil || r.ListenPort != DefaultRealityListenPort || exitSpec.Firewall.RealityPort != DefaultRealityListenPort {
		t.Errorf("exit after rollback: %+v, firewall port %d", r, exitSpec.Firewall.RealityPort)
	}
	ts := tunnelsByName(t, s, "master-xa-1")
	rt := ts["exit-de-1-reality"]
	if rt.Reality == nil || rt.Reality.Reverse || rt.Endpoint == "" {
		t.Errorf("master tunnel after rollback: %+v", rt)
	}
	if spec := renderMaster(t, s, "master-xa-1"); spec.Master.RealityPortal != nil {
		t.Error("portal kept after rollback")
	}
}

// Every node renders every ~30 s; a standing refusal is logged once, not once
// per render of each of the three nodes.
func TestRealityReverseWarnsOnceAcrossRenders(t *testing.T) {
	s := newReverseSetup(t)
	setWireVersion(t, s.st, "master-xa-2", api.WireRealityReverse-1)
	for range 5 {
		for _, n := range []string{"exit-de-1", "master-xa-1", "master-xa-2"} {
			if _, err := s.b.RenderNodeSpec(context.Background(), n); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n := strings.Count(s.logs.String(), "master not ready"); n != 1 {
		t.Errorf("warned %d times, want once:\n%s", n, s.logs.String())
	}
}
