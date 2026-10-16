package keybroker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func tunnelsByName(t *testing.T, s reverseSetup, master string) map[string]domain.ExitTunnel {
	t.Helper()
	spec, err := s.b.RenderNodeSpec(context.Background(), master)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]domain.ExitTunnel{}
	for _, et := range spec.Master.ExitTunnels {
		out[et.Name] = et
	}
	return out
}

// mihomo reaches a reverse tunnel through the portal's SOCKS inbound: nothing in
// the tunnel names an address, a key or a VLESS identity of the exit.
func TestMasterSpecReverseTunnelIsSocksShaped(t *testing.T) {
	s := newReverseSetup(t)
	for _, m := range []string{"master-xa-1", "master-xa-2"} {
		rt, ok := tunnelsByName(t, s, m)["exit-de-1-reality"]
		if !ok {
			t.Fatalf("%s: no reality tunnel", m)
		}
		if rt.Endpoint != "" || rt.Transport != domain.TransportRealityXHTTP || rt.Reality == nil || !rt.Reality.Reverse {
			t.Errorf("%s: tunnel = %+v", m, rt)
		}
		if r := rt.Reality; r.UUID != "" || r.PublicKey != "" || r.ShortID != "" || r.XHTTPPath != "" {
			t.Errorf("%s: reverse tunnel carries forward identity: %+v", m, r)
		}
	}
}

// A master that is not ready loses its REALITY tunnel to the exit and nothing
// else: its AmneziaWG tunnel stays, and the other master keeps its reverse one.
func TestMasterSpecNotReadyLosesOnlyItsRealityTunnel(t *testing.T) {
	s := newReverseSetup(t)
	setWireVersion(t, s.st, "master-xa-2", 13)
	ts2 := tunnelsByName(t, s, "master-xa-2")
	if _, ok := ts2["exit-de-1-reality"]; ok {
		t.Error("a master on wire 13 got a reverse tunnel")
	}
	if _, ok := ts2["exit-de-1"]; !ok {
		t.Error("the master's AmneziaWG tunnel went with it")
	}
	if rt, ok := tunnelsByName(t, s, "master-xa-1")["exit-de-1-reality"]; !ok || !rt.Reality.Reverse {
		t.Error("the ready master lost its reverse tunnel")
	}
}

// Standby semantics are the transport's, not the mode's: exactly one of the
// pair carries traffic.
func TestReverseDrainedSemanticsUnchanged(t *testing.T) {
	s := newReverseSetup(t)
	ts := tunnelsByName(t, s, "master-xa-1")
	if ts["exit-de-1"].Drained || !ts["exit-de-1-reality"].Drained {
		t.Errorf("AWG active: awg drained=%v reality drained=%v", ts["exit-de-1"].Drained, ts["exit-de-1-reality"].Drained)
	}
	s.b.fleet.Exits[0].ActiveTransport = string(domain.TransportRealityXHTTP)
	ts = tunnelsByName(t, s, "master-xa-1")
	if !ts["exit-de-1"].Drained || ts["exit-de-1-reality"].Drained {
		t.Errorf("REALITY active: awg drained=%v reality drained=%v", ts["exit-de-1"].Drained, ts["exit-de-1-reality"].Drained)
	}
}

func TestMasterSpecUnarmedIsByteIdentical(t *testing.T) {
	render := func(s reverseSetup) string {
		t.Helper()
		spec, err := s.b.RenderNodeSpec(context.Background(), "master-xa-1")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(spec)
		return string(b)
	}
	off := newReverseSetup(t)
	off.b.fleet.Exits[0].Transports.Reality.ExitInitiated = false
	want := render(off)
	closed := newReverseSetup(t)
	closed.b.reverseOpen = false
	if got := render(closed); got != want {
		t.Errorf("gate closed: master spec differs from flag off\n got %s\nwant %s", got, want)
	}
}
