package api

import (
	"reflect"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestRealityBridgeRoundTrip(t *testing.T) {
	bridge := &domain.RealityBridgeSpec{Portals: []domain.RealityPortalPeer{
		{Master: "m1", Address: "203.0.113.1:48123", PublicKey: "pk1", UUID: "u1", ShortID: "0a", ServerName: "a.example", Fingerprint: "firefox"},
		{Master: "m2", Address: "203.0.113.2:41000", PublicKey: "pk2", UUID: "u2", ShortID: "0b", ServerName: "b.example"},
	}}
	spec := domain.NodeSpec{Role: domain.RoleExit, Reality: &domain.RealityServerSpec{AllowIPv6: true, Image: "img", Bridge: bridge}}
	got := SpecFromProto(SpecToProto(spec))
	if !reflect.DeepEqual(got.Reality.Bridge, bridge) {
		t.Fatalf("bridge after round trip = %+v, want %+v", got.Reality.Bridge, bridge)
	}
}

func TestRealityTunnelReverseRoundTrip(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		ExitTunnels: []domain.ExitTunnel{{Name: "exit-a", Reality: &domain.RealityTunnel{Reverse: true}}},
	}}
	got := SpecFromProto(SpecToProto(spec))
	if !got.Master.ExitTunnels[0].Reality.Reverse {
		t.Fatal("RealityTunnel.Reverse lost in round trip")
	}
}

func TestRealityPortalRoundTrip(t *testing.T) {
	portal := &domain.RealityPortalSpec{
		ListenPort: 48123, SocksPort: 10808, ServerName: "a.example", Dest: "a.example:443", AllowIPv6: true, Image: "img",
		Clients: []domain.RealityPortalClient{{Exit: "e1", UUID: "u1", ShortID: "0a"}, {Exit: "e2", UUID: "u2", ShortID: "0b"}},
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{RealityPortal: portal}}
	got := SpecFromProto(SpecToProto(spec))
	if !reflect.DeepEqual(got.Master.RealityPortal, portal) {
		t.Fatalf("portal after round trip = %+v, want %+v", got.Master.RealityPortal, portal)
	}
}

// nil must stay nil: a zero-value struct would put every exit in bridge mode and
// give every master a portal.
func TestRealityReverseNilStaysNil(t *testing.T) {
	spec := domain.NodeSpec{
		Role:    domain.RoleMaster,
		Reality: &domain.RealityServerSpec{ListenPort: 443},
		Master:  &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{{Name: "e", Reality: &domain.RealityTunnel{UUID: "u"}}}},
	}
	got := SpecFromProto(SpecToProto(spec))
	if got.Reality.Bridge != nil {
		t.Errorf("Bridge = %+v, want nil", got.Reality.Bridge)
	}
	if got.Master.RealityPortal != nil {
		t.Errorf("RealityPortal = %+v, want nil", got.Master.RealityPortal)
	}
	if got.Master.ExitTunnels[0].Reality.Reverse {
		t.Error("Reverse = true, want false")
	}
}
