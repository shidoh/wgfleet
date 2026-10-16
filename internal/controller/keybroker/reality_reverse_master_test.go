package keybroker

import (
	"context"
	"encoding/json"
	"strconv"
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

func renderMaster(t *testing.T, s reverseSetup, name string) domain.NodeSpec {
	t.Helper()
	spec, err := s.b.RenderNodeSpec(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestMasterSpecPortalListsArmedExitsOnly(t *testing.T) {
	s := newReverseSetup(t)
	spec := renderMaster(t, s, "master-xa-1")
	p := spec.Master.RealityPortal
	if p == nil {
		t.Fatal("no portal on a master an exit dials")
	}
	m := s.b.fleet.Masters[1] // master-xa-1 (listed second)
	if p.ListenPort != m.RealityPortalListenPort() || p.SocksPort != domain.RealityPortalSocksPort ||
		p.ServerName != DefaultRealitySNI || p.Dest != DefaultRealitySNI+":443" || p.Image == "" {
		t.Errorf("portal = %+v", p)
	}
	uuid, sid := portalIDs("exit-de-1", "master-xa-1")
	if len(p.Clients) != 1 || p.Clients[0] != (domain.RealityPortalClient{Exit: "exit-de-1", UUID: uuid, ShortID: sid}) {
		t.Errorf("clients = %+v", p.Clients)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("rendered portal invalid: %v", err)
	}
	// The bridge dials exactly what the portal admits.
	exitSpec, err := s.b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	peer := exitSpec.Reality.Bridge.Portals[0]
	if peer.UUID != p.Clients[0].UUID || peer.ShortID != p.Clients[0].ShortID || peer.ServerName != p.ServerName ||
		peer.Address != "203.0.113.1:"+itoaPort(p.ListenPort) {
		t.Errorf("bridge peer %+v does not match the portal %+v", peer, p)
	}
	// Its world-facing port is open, and only it.
	found := 0
	for _, port := range spec.Firewall.PublicTCPPorts {
		if port == p.ListenPort {
			found++
		}
	}
	if found != 1 {
		t.Errorf("public TCP ports = %v, want the portal port once", spec.Firewall.PublicTCPPorts)
	}
}

func TestMasterSpecNoPortalWhenNoArmedExit(t *testing.T) {
	s := newReverseSetup(t)
	s.b.fleet.Exits[0].Transports.Reality.ExitInitiated = false
	spec := renderMaster(t, s, "master-xa-1")
	if spec.Master.RealityPortal != nil {
		t.Errorf("portal rendered with no exit in the mode: %+v", spec.Master.RealityPortal)
	}
	port := s.b.fleet.Masters[1].RealityPortalListenPort()
	for _, p := range spec.Firewall.PublicTCPPorts {
		if p == port {
			t.Error("portal port opened with no portal")
		}
	}
}

func TestMasterSpecPortalCamouflageFollowsTheMaster(t *testing.T) {
	s := newReverseSetup(t)
	s.b.fleet.Masters[1].RealityPortal.SNI = "ya.example"
	s.b.fleet.Masters[1].RealityPortal.DestDomain = "ya.example"
	p := renderMaster(t, s, "master-xa-1").Master.RealityPortal
	if p.ServerName != "ya.example" || p.Dest != "ya.example:443" {
		t.Errorf("portal camouflage = %q %q", p.ServerName, p.Dest)
	}
}

func itoaPort(p int) string { return strconv.Itoa(p) }
