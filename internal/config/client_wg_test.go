package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// hasClientAWGErr reports whether Validate flagged a client_awg-specific problem.
// The base config intentionally omits controller.store / pki, so Validate always
// returns SOME error; we inspect only for the client_awg part.
func hasClientAWGErr(c ControllerConfig) bool {
	err := c.Validate()
	return err != nil && strings.Contains(err.Error(), "client_awg")
}

func masterWith(name string, awg ClientAWGConfig) MasterConfig {
	return MasterConfig{Name: name, MgmtAddr: "10.20.0.1", ClientAWG: awg}
}

func TestClientAWGBackendValidation(t *testing.T) {
	base := func(backend string) ControllerConfig {
		return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
			masterWith("m1", ClientAWGConfig{
				ListenPort: 443, AddressPool: "10.80.0.0/24", Backend: backend,
			}),
		}}}
	}
	for _, ok := range []string{"", "kernel", "userspace"} {
		if hasClientAWGErr(base(ok)) {
			t.Errorf("backend %q should be accepted", ok)
		}
	}
	if !hasClientAWGErr(base("wireguard-go")) {
		t.Error("unknown client_awg.backend should fail validation")
	}
}

// Managing the interface ourselves means rendering it from the pool, so the pool
// stops being optional the moment the knob is on.
func TestClientAWGManagedRequiresPool(t *testing.T) {
	managed := true
	cfg := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
		masterWith("m1", ClientAWGConfig{ListenPort: 443, Managed: &managed}),
	}}}
	if !hasClientAWGErr(cfg) {
		t.Error("managed client_awg without an address_pool should fail validation")
	}

	unmanaged := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
		masterWith("m1", ClientAWGConfig{ListenPort: 443}),
	}}}
	if hasClientAWGErr(unmanaged) {
		t.Error("an unmanaged master without a pool is still valid (wg-easy owns the interface)")
	}
}

// Two masters may not hand out addresses from overlapping pools: a client address
// would then be ambiguous the moment traffic crosses between gateways. This is a
// multi-master precondition (ADR-0027) that costs nothing to enforce now.
func TestClientAWGPoolsMustNotOverlap(t *testing.T) {
	tests := []struct {
		name       string
		first      string
		second     string
		wantErr    bool
		wantReason string
	}{
		{name: "disjoint", first: "10.80.0.0/24", second: "10.81.0.0/24", wantErr: false},
		{name: "identical", first: "10.80.0.0/24", second: "10.80.0.0/24", wantErr: true, wantReason: "overlaps"},
		{name: "contained", first: "10.80.0.0/16", second: "10.80.5.0/24", wantErr: true, wantReason: "overlaps"},
		{name: "containing", first: "10.80.5.0/24", second: "10.80.0.0/16", wantErr: true, wantReason: "overlaps"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
				masterWith("m1", ClientAWGConfig{ListenPort: 443, AddressPool: tc.first}),
				masterWith("m2", ClientAWGConfig{ListenPort: 443, AddressPool: tc.second}),
			}}}
			err := cfg.Validate()
			got := err != nil && strings.Contains(err.Error(), "overlaps")
			if got != tc.wantErr {
				t.Fatalf("overlap detected = %v, want %v (err = %v)", got, tc.wantErr, err)
			}
		})
	}
}

func TestClientAWGResolvers(t *testing.T) {
	// Unset: the fleet keeps running on wg-easy and the kernel backend.
	m := masterWith("m1", ClientAWGConfig{})
	if m.ClientAWGManaged() {
		t.Error("ClientAWGManaged() = true for an unset knob, want false")
	}
	if got := m.ClientAWGBackend(); got != domain.ClientWGBackendKernel {
		t.Errorf("ClientAWGBackend() = %q, want kernel", got)
	}
	// MTU unset means "let the keybroker derive it from the hop chain" (it already
	// does, via clientFacingMTU); the knob is an override, not a second source of
	// truth, so an unset value must stay 0 rather than pin a constant here.
	if got := m.ClientAWGMTU(); got != 0 {
		t.Errorf("ClientAWGMTU() = %d for an unset knob, want 0 (derived)", got)
	}

	// Explicit values win.
	managed := true
	m = masterWith("m1", ClientAWGConfig{
		Managed: &managed, Backend: "userspace", MTU: 1420,
		DNS: []string{"10.80.0.1"}, AllowedIPs: []string{"0.0.0.0/0"},
	})
	if !m.ClientAWGManaged() {
		t.Error("ClientAWGManaged() = false for managed: true")
	}
	if got := m.ClientAWGBackend(); got != domain.ClientWGBackendUserspace {
		t.Errorf("ClientAWGBackend() = %q, want userspace", got)
	}
	if got := m.ClientAWGMTU(); got != 1420 {
		t.Errorf("ClientAWGMTU() = %d, want 1420", got)
	}
	if got := m.ClientAWGDNS(); len(got) != 1 || got[0] != "10.80.0.1" {
		t.Errorf("ClientAWGDNS() = %v, want [10.80.0.1]", got)
	}
	if got := m.ClientAWGAllowedIPs(); len(got) != 1 || got[0] != "0.0.0.0/0" {
		t.Errorf("ClientAWGAllowedIPs() = %v, want [0.0.0.0/0]", got)
	}
}

// The wg-easy era put the client DNS and AllowedIPs under compose. An existing
// manifest must keep working when the interface changes hands, so those values
// are inherited when the new keys are unset.
func TestClientAWGInheritsComposeEraValues(t *testing.T) {
	m := MasterConfig{
		Name:     "m1",
		MgmtAddr: "10.20.0.1",
		Compose: ComposeConfig{
			ClientDNS:        []string{"10.80.0.1", "10.81.0.1"},
			ClientAllowedIPs: "0.0.0.0/5, 8.0.0.0/7",
		},
	}
	dns := m.ClientAWGDNS()
	if len(dns) != 2 || dns[0] != "10.80.0.1" || dns[1] != "10.81.0.1" {
		t.Errorf("ClientAWGDNS() = %v, want the compose-era list", dns)
	}
	allowed := m.ClientAWGAllowedIPs()
	if len(allowed) != 2 || allowed[0] != "0.0.0.0/5" || allowed[1] != "8.0.0.0/7" {
		t.Errorf("ClientAWGAllowedIPs() = %v, want the compose-era list split and trimmed", allowed)
	}
}

// An IPv6 default route in the client AllowedIPs is the an earlier finding black hole and
// must be refused in the manifest, not just in the domain validator.
func TestClientAWGRejectsIPv6DefaultRoute(t *testing.T) {
	cfg := ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
		masterWith("m1", ClientAWGConfig{
			ListenPort: 443, AddressPool: "10.80.0.0/24",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}),
	}}}
	if !hasClientAWGErr(cfg) {
		t.Error("client_awg.allowed_ips with ::/0 should fail validation")
	}
}

// awg3Config builds a master whose client leg asks for a 3.x mode.
func awg3Config(mode string, managed bool) ControllerConfig {
	c := ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24", AWG3: mode}
	if managed {
		c.Managed = &managed
	}
	return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{masterWith("m1", c)}}}
}

func TestClientAWG3ModeValidation(t *testing.T) {
	for _, ok := range []string{"", "off", "timers", "full", "TIMERS", " full "} {
		if hasClientAWGErr(awg3Config(ok, true)) {
			t.Errorf("client_awg.awg3 %q should be accepted", ok)
		}
	}
	for _, bad := range []string{"true", "3", "yes", "headers", "3.1"} {
		if !hasClientAWGErr(awg3Config(bad, true)) {
			t.Errorf("client_awg.awg3 %q should fail validation", bad)
		}
	}
}

// While wg-easy owns the leg there is nowhere to put a 3.x parameter — its schema
// has no column for one — so the knob would silently do nothing. Silently doing
// nothing is the failure this project refuses: the operator would believe their
// clients were on 3.x while every packet stayed 2.0.
func TestClientAWG3RequiresAManagedInterface(t *testing.T) {
	if !hasClientAWGErr(awg3Config("timers", false)) {
		t.Error("client_awg.awg3 without managed:true should fail validation")
	}
	if hasClientAWGErr(awg3Config("off", false)) {
		t.Error("an unmanaged leg explicitly on 2.0 is the normal shape and must be accepted")
	}
}

func TestClientAWG3Resolves(t *testing.T) {
	for in, want := range map[string]ClientAWG3Mode{
		"": ClientAWG3Off, "off": ClientAWG3Off, "nonsense": ClientAWG3Off,
		"timers": ClientAWG3Timers, " Timers ": ClientAWG3Timers,
		"full": ClientAWG3Full, "FULL": ClientAWG3Full,
	} {
		got := MasterConfig{ClientAWG: ClientAWGConfig{AWG3: in}}.ClientAWG3()
		if got != want {
			t.Errorf("ClientAWG3(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientAWGKeepaliveValidation(t *testing.T) {
	base := func(v string) ControllerConfig {
		return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
			masterWith("m1", ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24", Keepalive: v}),
		}}}
	}
	for _, ok := range []string{"", "25", "15-25", "120"} {
		if hasClientAWGErr(base(ok)) {
			t.Errorf("client_awg.keepalive %q should be accepted", ok)
		}
	}
	// A keepalive above the shortest common NAT timeout silently costs the master
	// its reachability to idle clients, so the bound is enforced rather than
	// documented.
	for _, bad := range []string{"0", "600", "25-15", "soon"} {
		if !hasClientAWGErr(base(bad)) {
			t.Errorf("client_awg.keepalive %q should fail validation", bad)
		}
	}
}
