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

// awg3Config builds a master whose client leg asks for a 3.x mode. The fleet
// secret is set because "full" now requires one — this helper is about the MODE
// parsing, and a missing secret is a separate refusal with its own test.
func awg3Config(mode string, managed bool) ControllerConfig {
	c := ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24", AWG3: mode}
	if managed {
		c.Managed = &managed
	}
	return ControllerConfig{Fleet: FleetSection{
		AWG3Key: "secret://awg3-key",
		Masters: []MasterConfig{masterWith("m1", c)},
	}}
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

// The expansion is the product's answer to "a client at home cannot reach its own
// LAN". A typo in it must fail at startup, not quietly produce a routing table
// nobody intended.
func TestClientAWGExcludeFromTunnelValidation(t *testing.T) {
	base := func(exclude, through []string) ControllerConfig {
		return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
			masterWith("m1", ClientAWGConfig{
				ListenPort: 443, AddressPool: "10.80.0.0/24",
				ExcludeFromTunnel: exclude, RouteThroughCIDRs: through,
			}),
		}}}
	}
	if hasClientAWGErr(base([]string{"172.16.0.0/12"}, []string{"172.19.57.0/24"})) {
		t.Error("a valid exclusion pair should be accepted")
	}
	if !hasClientAWGErr(base([]string{"nonsense"}, nil)) {
		t.Error("a malformed exclusion should fail validation")
	}
	// Putting a network back when nothing was taken out does nothing at all, and a
	// setting that silently does nothing is the failure this project refuses.
	if !hasClientAWGErr(base(nil, []string{"10.0.0.0/8"})) {
		t.Error("route_through_cidrs without exclude_from_tunnel should fail validation")
	}
}

// The resolved list is what a client actually gets, so assert membership rather
// than the shape of the expansion.
func TestClientAWGAllowedIPsResolution(t *testing.T) {
	m := masterWith("m1", ClientAWGConfig{
		ExcludeFromTunnel: []string{"172.16.0.0/12", "192.168.0.0/16"},
		RouteThroughCIDRs: []string{"10.0.0.0/8", "172.19.57.0/24"},
	})
	got := strings.Join(m.ClientAWGAllowedIPs(), ",")
	if strings.Contains(got, "0.0.0.0/0") {
		t.Errorf("the default route survived the exclusion: %s", got)
	}
	if !strings.Contains(got, "172.19.57.0/24") {
		t.Errorf("the re-added work subnet is missing: %s", got)
	}

	// allowed_ips is the escape hatch and wins outright.
	m.ClientAWG.AllowedIPs = []string{"0.0.0.0/0"}
	if v := m.ClientAWGAllowedIPs(); len(v) != 1 || v[0] != "0.0.0.0/0" {
		t.Errorf("allowed_ips did not override the expansion: %v", v)
	}
}

// The exclusion an operator will actually write, copied from routing.direct_cidrs
// in the same manifest, takes the client pool and the client DNS server out of
// the tunnel. Nothing downstream can catch it: the expansion is arithmetic, the
// list is well-formed and the rendered config is valid. It surfaces only as a
// person saying nothing works.
func TestExcludeFromTunnelMustNotCutOffTheGatewayOrDNS(t *testing.T) {
	base := func() MasterConfig {
		return MasterConfig{
			Name: "m1", MgmtAddr: "10.20.0.1",
			ClientAWG: ClientAWGConfig{
				ListenPort:  443,
				AddressPool: "10.80.0.0/24",
				DNS:         []string{"10.20.25.254"},
			},
		}
	}

	m := base()
	m.ClientAWG.ExcludeFromTunnel = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	errs := validateClientAWG(0, m, FleetSection{})
	var gotPool, gotDNS bool
	for _, err := range errs {
		if strings.Contains(err.Error(), "10.80.0.0/24") {
			gotPool = true
		}
		if strings.Contains(err.Error(), "10.20.25.254") {
			gotDNS = true
		}
	}
	if !gotPool {
		t.Errorf("excluding the client pool was accepted; errors: %v", errs)
	}
	if !gotDNS {
		t.Errorf("excluding the client DNS server was accepted; errors: %v", errs)
	}

	// Putting them back is the documented fix, and it must clear both.
	m.ClientAWG.RouteThroughCIDRs = []string{"10.80.0.0/24", "10.20.0.0/16"}
	if errs := validateClientAWG(0, m, FleetSection{}); len(errs) != 0 {
		t.Errorf("route_through_cidrs did not resolve the exclusion: %v", errs)
	}

	// An exclusion that touches neither is fine as it stands.
	ok := base()
	ok.ClientAWG.ExcludeFromTunnel = []string{"192.168.0.0/16"}
	if errs := validateClientAWG(0, ok, FleetSection{}); len(errs) != 0 {
		t.Errorf("a harmless exclusion was refused: %v", errs)
	}
}

// Header protection without a fleet secret must be refused, not silently derived
// from the public salt.
//
// Every other AmneziaWG parameter is safe to derive from a compiled-in salt —
// they work by being non-default, not by being unknown. The header-protection key
// is a chacha20 key whose whole purpose is that an observer does not have it, and
// this repository is meant to be published.
func TestAWG3HeaderProtectionRequiresAFleetSecret(t *testing.T) {
	on := true
	base := func() ControllerConfig {
		return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{
			{Name: "m1", MgmtAddr: "10.20.0.1", ClientAWG: ClientAWGConfig{ListenPort: 443, AddressPool: "10.80.0.0/24"}},
		}}}
	}

	// Fleet-wide 3.x on an exit tunnel.
	c := base()
	c.Fleet.AWG3 = &on
	if errs := validateAWG3Secret(c); len(errs) == 0 {
		t.Error("fleet.awg3 was accepted with no fleet.awg3_key")
	}

	// The client interface's "full" mode.
	c = base()
	c.Fleet.Masters[0].ClientAWG.Managed = &on
	c.Fleet.Masters[0].ClientAWG.AWG3 = "full"
	errs := validateAWG3Secret(c)
	if len(errs) == 0 {
		t.Fatal("client_awg.awg3: full was accepted with no fleet.awg3_key")
	}
	if !strings.Contains(errs[0].Error(), "timers") {
		t.Errorf("the refusal does not point at the mode that needs no secret: %v", errs[0])
	}

	// Timers need no secret — they are the half that keeps every existing config
	// working, and refusing them here would be refusing the whole feature.
	c = base()
	c.Fleet.Masters[0].ClientAWG.Managed = &on
	c.Fleet.Masters[0].ClientAWG.AWG3 = "timers"
	if errs := validateAWG3Secret(c); len(errs) != 0 {
		t.Errorf("timers were refused for want of a secret they do not use: %v", errs)
	}

	// And with the secret set, everything is allowed.
	c = base()
	c.Fleet.AWG3 = &on
	c.Fleet.AWG3Key = "secret://awg3-key"
	if errs := validateAWG3Secret(c); len(errs) != 0 {
		t.Errorf("3.x was refused despite a configured secret: %v", errs)
	}
}

// The validator must see the resolver the CONTROLLER will actually hand out, not
// just the one the operator wrote down.
//
// It used to read only client_awg.dns / compose.client_dns. A manifest that set
// neither — the shipped shape, because the resolver "defaults to the exits' mgmt
// addresses" — therefore had no DNS to check, passed validation, and the broker
// then handed clients a resolver that exclude_from_tunnel had removed from the
// tunnel. The result is a config that connects and resolves nothing, which reaches
// the operator weeks later as "it doesn't work".
func TestTunnelReachesItselfChecksTheDerivedResolver(t *testing.T) {
	fleet := FleetSection{Exits: []ExitConfig{{Name: "exit-de-1", MgmtAddr: "192.168.105.2"}}}
	m := MasterConfig{Name: "master-xa-1"}
	m.ClientAWG.AddressPool = "10.80.0.0/24"
	// Neither client_awg.dns nor compose.client_dns — the shipped shape.
	m.ClientAWG.ExcludeFromTunnel = []string{"192.168.0.0/16"}

	errs := validateTunnelReachesItself(0, m, fleet)
	var named bool
	for _, e := range errs {
		if strings.Contains(e.Error(), "192.168.105.2") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the excluded resolver was not caught; clients would resolve nothing: %v", errs)
	}

	// Routing it back in clears the finding.
	m.ClientAWG.RouteThroughCIDRs = []string{"192.168.105.0/24"}
	for _, e := range validateTunnelReachesItself(0, m, fleet) {
		if strings.Contains(e.Error(), "192.168.105.2") {
			t.Errorf("still reported after route_through_cidrs put it back: %v", e)
		}
	}
}

// With master-tier blocky the resolver is the gateway, which is inside the pool and
// therefore always in the tunnel — the check must not invent a problem there.
func TestTunnelReachesItselfAcceptsTheMasterGateway(t *testing.T) {
	m := MasterConfig{Name: "master-xa-1", DNSFilter: true}
	m.ClientAWG.AddressPool = "10.80.0.0/24"
	m.ClientAWG.ExcludeFromTunnel = []string{"192.168.0.0/16"}
	if errs := validateTunnelReachesItself(0, m, FleetSection{}); len(errs) != 0 {
		t.Errorf("the master gateway was reported unreachable from its own tunnel: %v", errs)
	}
}

// The namespace link is an address pool like any other, and the one an operator is
// most likely to pick badly: it is a /30 that exists only on the master, so nothing
// else in the fleet mentions it and a collision stays invisible until traffic to
// that range disappears into a namespace.
func TestNetnsCIDRMustNotOverlapAnyPool(t *testing.T) {
	f := FleetSection{
		Masters: []MasterConfig{{
			Name:      "m0",
			ClientAWG: ClientAWGConfig{AddressPool: "10.73.0.0/24"},
			Mihomo:    MihomoConfig{NetnsCIDR: "10.73.0.0/30"},
		}},
	}
	errs := validateAddressPoolsDisjoint(f)
	if len(errs) == 0 {
		t.Fatal("a namespace link inside the client pool was accepted")
	}
	if !strings.Contains(errs[0].Error(), "netns_cidr") {
		t.Errorf("the error does not name the knob: %v", errs[0])
	}
}

// The default is RFC 6598 and collides with nothing this fleet uses.
func TestDefaultNetnsCIDRIsAccepted(t *testing.T) {
	f := FleetSection{
		Masters: []MasterConfig{{
			Name:      "m0",
			ClientAWG: ClientAWGConfig{AddressPool: "10.73.0.0/24"},
			Mihomo:    MihomoConfig{NetnsCIDR: "100.127.255.0/30"},
		}},
		Exits: []ExitConfig{{Name: "e0", AddressPool: "10.81.0.0/24"}},
	}
	if errs := validateAddressPoolsDisjoint(f); len(errs) != 0 {
		t.Fatalf("a healthy fleet was rejected: %v", errs)
	}
}

// A subscription refresh over AWG dials the client portal from inside the tunnel.
// exclude_from_tunnel can take the portal's own bind address (or the management
// overlay it lives on) out of the AllowedIPs without anything refusing to start —
// the manifest is well-formed, the pool and DNS checks above pass, and the fleet
// runs for weeks before someone reports "the app never gets the fleet's new state".
// This is a WARN, never a hard error: refusing the config could stop a live
// controller on upgrade over a tunnel shape that has run fine otherwise.
func TestClientAWGTunnelWarningsFlagsAnUncoveredPortal(t *testing.T) {
	base := func() ControllerConfig {
		return ControllerConfig{
			Controller: ControllerSection{ClientPortal: "10.20.0.10:9001"},
			Fleet: FleetSection{
				MgmtSubnet: "10.20.0.0/16",
				Masters: []MasterConfig{{
					Name: "master-xa-1", MgmtAddr: "10.20.0.1",
					ClientAWG: ClientAWGConfig{AddressPool: "10.80.0.0/24"},
				}},
			},
		}
	}

	// No exclude_from_tunnel at all: the default route covers everything, so there
	// is nothing to warn about even though the portal is configured.
	if got := ClientAWGTunnelWarnings(base()); len(got) != 0 {
		t.Errorf("no exclusion but warnings were raised: %v", got)
	}

	// Excluding RFC1918 (the operator's LAN, the usual reason to exclude anything)
	// also takes out the portal's 10.20.0.10 and the mgmt overlay 10.20.0.0/16.
	c := base()
	c.Fleet.Masters[0].ClientAWG.ExcludeFromTunnel = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	warnings := ClientAWGTunnelWarnings(c)
	var gotPortal, gotMgmt bool
	for _, w := range warnings {
		if strings.Contains(w, "master-xa-1") && strings.Contains(w, "10.20.0.10") {
			gotPortal = true
		}
		if strings.Contains(w, "master-xa-1") && strings.Contains(w, "10.20.0.0/16") {
			gotMgmt = true
		}
	}
	if !gotPortal {
		t.Errorf("an uncovered portal bind address was not flagged: %v", warnings)
	}
	if !gotMgmt {
		t.Errorf("an uncovered mgmt overlay was not flagged: %v", warnings)
	}

	// route_through_cidrs puts both back in: no warnings.
	c.Fleet.Masters[0].ClientAWG.RouteThroughCIDRs = []string{"10.20.0.0/16"}
	if got := ClientAWGTunnelWarnings(c); len(got) != 0 {
		t.Errorf("route_through_cidrs did not resolve the exclusion: %v", got)
	}

	// No controller.client_portal at all: nothing to warn about on that front, even
	// with the same exclusion (the mgmt overlay is still flagged on its own).
	c2 := base()
	c2.Controller.ClientPortal = ""
	c2.Fleet.Masters[0].ClientAWG.ExcludeFromTunnel = []string{"10.0.0.0/8"}
	for _, w := range ClientAWGTunnelWarnings(c2) {
		if strings.Contains(w, "10.20.0.10") {
			t.Errorf("warned about a portal that is not configured: %v", w)
		}
	}
}
