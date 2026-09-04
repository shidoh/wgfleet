package mihomo

import (
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// tunnels builds a dual-transport exit the way the keybroker does: two proxies,
// one per transport, with the INACTIVE one drained (ADR-0025).
func dualTransport(exit string, realityActive, exitDrained bool) []domain.ExitTunnel {
	return []domain.ExitTunnel{
		{
			Name:      exit,
			Transport: domain.TransportAWG,
			Drained:   exitDrained || realityActive,
		},
		{
			Name:      exit + domain.RealityProxySuffix,
			Transport: domain.TransportRealityXHTTP,
			Drained:   exitDrained || !realityActive,
		},
	}
}

func names(ts []StandbyTunnel) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Proxy)
	}
	return out
}

// The standby transport of a dual-transport exit is drained on purpose so no new
// traffic routes to it — and that is exactly why nothing probes it: it joins no
// tier, so neither the tier decision nor the standby-TIER warm probe touches it.
// Measured on the live fleet 2026-09-04: four standby proxies had never been
// health-checked once and still reported alive=1, which is mihomo's default for
// an untested proxy, not a measurement. This function is what makes them
// probeable.
func TestStandbyTransportsFindsTheInactiveTransport(t *testing.T) {
	spec := domain.MasterSpec{ExitTunnels: dualTransport("vn0", false, false)}
	got := StandbyTransports(spec)
	if len(got) != 1 {
		t.Fatalf("want exactly the inactive transport, got %v", names(got))
	}
	if got[0].Proxy != "vn0-reality" {
		t.Errorf("standby proxy = %q, want vn0-reality (awg is active here)", got[0].Proxy)
	}
	if got[0].Exit != "vn0" {
		t.Errorf("exit = %q, want vn0 — the metric labels a NODE, not a proxy name", got[0].Exit)
	}
	if got[0].Transport != domain.TransportRealityXHTTP {
		t.Errorf("transport = %q, want reality-xhttp", got[0].Transport)
	}

	// Flip which transport is active; the standby follows.
	spec = domain.MasterSpec{ExitTunnels: dualTransport("1cnode004", true, false)}
	got = StandbyTransports(spec)
	if len(got) != 1 || got[0].Proxy != "1cnode004" || got[0].Transport != domain.TransportAWG {
		t.Fatalf("with reality active the AWG proxy is the standby, got %v", names(got))
	}
}

// The discriminator that matters. An exit the operator drained — or that the
// throughput watchdog auto-suspended — has BOTH its transports drained, because
// the controller ORs that decision into each of them. Probing those would be
// wrong twice over: it dials an exit deliberately taken out of service, and it
// reports "your standby is broken" about a node nobody intends to switch to.
func TestStandbyTransportsIgnoresAFullyDrainedExit(t *testing.T) {
	spec := domain.MasterSpec{ExitTunnels: dualTransport("vn0", false, true)}
	if got := StandbyTransports(spec); len(got) != 0 {
		t.Fatalf("a drained exit has no standby transport, only a drained one; got %v", names(got))
	}
}

// A single-transport exit has nothing to fall back to, so it contributes nothing
// — not an entry that would read as a broken standby forever.
func TestStandbyTransportsIgnoresSingleTransportExits(t *testing.T) {
	spec := domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "pn8-reality", Transport: domain.TransportRealityXHTTP},
		{Name: "anz3", Transport: domain.TransportAWG},
	}}
	if got := StandbyTransports(spec); len(got) != 0 {
		t.Fatalf("single-transport exits have no standby, got %v", names(got))
	}
}

// A drained single-transport exit is likewise not a standby: there is no live
// sibling, so nothing is being kept in reserve.
func TestStandbyTransportsIgnoresADrainedSingleTransportExit(t *testing.T) {
	spec := domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "anz3", Transport: domain.TransportAWG, Drained: true},
	}}
	if got := StandbyTransports(spec); len(got) != 0 {
		t.Fatalf("a drained lone transport is not a standby, got %v", names(got))
	}
}

func TestStandbyTransportsAcrossTheFleet(t *testing.T) {
	var tunnels []domain.ExitTunnel
	tunnels = append(tunnels, dualTransport("vn0", false, false)...)      // standby: vn0-reality
	tunnels = append(tunnels, dualTransport("1cnode004", true, false)...) // standby: 1cnode004
	tunnels = append(tunnels, dualTransport("vn2", false, true)...)       // drained exit: none
	tunnels = append(tunnels, domain.ExitTunnel{Name: "pn8-reality", Transport: domain.TransportRealityXHTTP})

	got := names(StandbyTransports(domain.MasterSpec{ExitTunnels: tunnels}))
	want := []string{"vn0-reality", "1cnode004"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (order follows the spec so the probe load is stable)", got, want)
		}
	}
}
