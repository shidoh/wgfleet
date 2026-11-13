package keybroker

import (
	"context"
	"slices"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// camouflageSetup is the reverse fixture with every node on wire 16.
func camouflageSetup(t *testing.T) reverseSetup {
	t.Helper()
	s := newReverseSetup(t)
	for _, id := range []string{"master-xa-1", "master-xa-2", "exit-de-1"} {
		setWireVersion(t, s.st, id, api.WireCamouflage)
	}
	return s
}

func (s reverseSetup) render(t *testing.T, id string) domain.NodeSpec {
	t.Helper()
	spec, err := s.b.RenderNodeSpec(context.Background(), id)
	if err != nil {
		t.Fatalf("render %s: %v", id, err)
	}
	return spec
}

func (s reverseSetup) report(t *testing.T, id, camouflageDomain string) {
	t.Helper()
	if err := s.st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: id, State: domain.StateReady, CamouflageDomain: camouflageDomain,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCamouflageSpecRendersForAWire16Node(t *testing.T) {
	s := camouflageSetup(t)
	s.b.fleet.Exits[0].Camouflage.Domain = "E1.Example.net"
	s.b.fleet.Camouflage.ACMEEmail = "ops@example.net"

	spec := s.render(t, "exit-de-1")
	c := spec.Camouflage
	if c == nil {
		t.Fatal("no camouflage in the spec of a wire-16 exit that has it")
	}
	if c.Domain != "e1.example.net" || c.PublicIP != "198.51.100.7" || c.ACMEEmail != "ops@example.net" || c.PublicHTTPS {
		t.Errorf("camouflage = %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("rendered camouflage invalid: %v", err)
	}
	if !slices.Contains(spec.Firewall.PublicTCPPorts, 80) || slices.Contains(spec.Firewall.PublicTCPPorts, 443) {
		t.Errorf("public tcp = %v, want 80 and not 443", spec.Firewall.PublicTCPPorts)
	}

	s.b.fleet.Exits[0].Camouflage.PublicHTTPS = true
	spec = s.render(t, "exit-de-1")
	if !slices.Contains(spec.Firewall.PublicTCPPorts, 443) {
		t.Errorf("public tcp = %v, want 443 with public_https", spec.Firewall.PublicTCPPorts)
	}
}

func TestCamouflageSpecWaitsForAWire16Agent(t *testing.T) {
	s := newReverseSetup(t) // wire 14
	s.b.fleet.Exits[0].Camouflage.Domain = "e1.example.net"
	spec := s.render(t, "exit-de-1")
	if spec.Camouflage != nil {
		t.Errorf("an agent below wire 16 got camouflage %+v", spec.Camouflage)
	}
	if slices.Contains(spec.Firewall.PublicTCPPorts, 80) {
		t.Error("TCP/80 opened for a site the agent cannot run")
	}
}

func TestMasterSpecCarriesItsCamouflage(t *testing.T) {
	s := camouflageSetup(t)
	s.b.fleet.Masters[1].Camouflage.Domain = "m1.example.net" // master-xa-1
	spec := s.render(t, "master-xa-1")
	if spec.Camouflage == nil || spec.Camouflage.Domain != "m1.example.net" || spec.Camouflage.PublicIP != "203.0.113.1" {
		t.Fatalf("camouflage = %+v", spec.Camouflage)
	}
	if !slices.Contains(spec.Firewall.PublicTCPPorts, 80) {
		t.Errorf("public tcp = %v, want 80", spec.Firewall.PublicTCPPorts)
	}
	if other := s.render(t, "master-xa-2"); other.Camouflage != nil {
		t.Errorf("master without camouflage got %+v", other.Camouflage)
	}
}

// The exit's dial to a portal sends the master's domain only while that master
// reports serving it; otherwise the fleet-default name, which connects either way.
func TestBridgeServerNameFollowsTheMastersReport(t *testing.T) {
	s := camouflageSetup(t)
	s.b.fleet.Masters[1].Camouflage.Domain = "m1.example.net" // master-xa-1
	sni := func() string {
		t.Helper()
		for _, p := range s.render(t, "exit-de-1").Reality.Bridge.Portals {
			if p.Master == "master-xa-1" {
				return p.ServerName
			}
		}
		t.Fatal("no portal for master-xa-1")
		return ""
	}
	if got := sni(); got != DefaultRealitySNI {
		t.Errorf("before any report: %q, want the fleet default", got)
	}
	s.report(t, "master-xa-1", "m1.example.net")
	if got := sni(); got != "m1.example.net" {
		t.Errorf("after the master reported its domain: %q", got)
	}
	s.report(t, "master-xa-1", "")
	if got := sni(); got != DefaultRealitySNI {
		t.Errorf("after the master went back to the default target: %q", got)
	}
	s.report(t, "master-xa-1", "m1.example.net")
	setWireVersion(t, s.st, "master-xa-1", api.WireRealityReverse)
	if got := sni(); got != DefaultRealitySNI {
		t.Errorf("master below wire 16: %q, want the fleet default", got)
	}
}

// The master's proxy toward a listening exit follows the exit's report the same way.
func TestMasterTunnelServerNameFollowsTheExitsReport(t *testing.T) {
	s := camouflageSetup(t)
	s.b.fleet.Exits[0].Transports.Reality.ExitInitiated = false
	s.b.fleet.Exits[0].Camouflage.Domain = "e1.example.net"
	_, pub, err := xray.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.st.SetNodeRealityKey(context.Background(), "exit-de-1", pub); err != nil {
		t.Fatal(err)
	}
	sni := func() string {
		t.Helper()
		for _, et := range s.render(t, "master-xa-1").Master.ExitTunnels {
			if et.Name == "exit-de-1-reality" && et.Reality != nil {
				return et.Reality.ServerName
			}
		}
		t.Fatal("no reality tunnel to exit-de-1")
		return ""
	}
	if got := sni(); got != DefaultRealitySNI {
		t.Errorf("before any report: %q, want the fleet default", got)
	}
	s.report(t, "exit-de-1", "e1.example.net")
	if got := sni(); got != "e1.example.net" {
		t.Errorf("after the exit reported its domain: %q", got)
	}
	s.report(t, "exit-de-1", "other.example.net")
	if got := sni(); got != DefaultRealitySNI {
		t.Errorf("a report for another domain: %q, want the fleet default", got)
	}
	// The exit's own inbound keeps the fleet default as its fallback name.
	if r := s.render(t, "exit-de-1").Reality; r == nil || r.ServerName != DefaultRealitySNI {
		t.Errorf("exit inbound = %+v, want the fleet-default fallback name", r)
	}
}
