package master

import (
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netfw"
)

// Only an AWG tunnel the controller armed is pinned: a REALITY proxy is TCP the
// master always opens, and an unarmed tunnel is one whose exit has not confirmed
// the endpoint yet — gating it would cut an exit still knocking elsewhere.
func TestPinnedExitsTakesOnlyArmedAWGTunnels(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "vn0", Endpoint: "198.51.100.7:30670", Transport: domain.TransportAWG, MasterAddr: "203.0.113.1:48310"},
		{Name: "vn0-reality", Endpoint: "198.51.100.7:443", Transport: domain.TransportRealityXHTTP, MasterAddr: "203.0.113.1:48310"},
		{Name: "vn1", Endpoint: "198.51.100.8:30671", Transport: domain.TransportAWG},
		{Name: "legacy", Endpoint: "198.51.100.9:30672", MasterAddr: "203.0.113.1:22000"},
	}}}
	got := pinnedExits(spec)
	want := []netfw.PinnedExit{
		{Exit: "198.51.100.7:30670", Master: "203.0.113.1:48310"},
		{Exit: "198.51.100.9:30672", Master: "203.0.113.1:22000"},
	}
	if len(got) != len(want) {
		t.Fatalf("pinnedExits = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pinnedExits[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
