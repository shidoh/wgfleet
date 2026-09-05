package main

import (
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netfw"
)

// masterSpec is the shape of a live master: a client interface on 443, a TPROXY
// listener, and a set of direct destinations.
func masterSpec() domain.NodeSpec {
	return domain.NodeSpec{
		WGServer: domain.WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"},
		Master: &domain.MasterSpec{
			BindAddress: "10.80.0.1",
			DirectCIDRs: []string{"172.29.0.0/16"},
			ClientWG:    &domain.ClientWGSpec{ListenPort: 443, ServerAddress: "10.80.0.1"},
		},
	}
}

// The regression this file exists for. `accounted` used to mean "a port this node
// holds", which made the client WG port accounted for by virtue of being the black
// hole: the check could not fail on 443, and the alert that watches it could not
// fire on the port the August 2026 outage was on.
func TestAccountedBlackHolesDoesNotExcuseTheClientWGPort(t *testing.T) {
	in := master0NATInput(t, masterSpec())
	if accountedUDPBlackHoles(in)[443] {
		t.Fatal("port 443 is excused: the udp-return check can never fail on the port the outage was on")
	}
}

// The excused set is the set the ruleset refuses, and it must track the ruleset.
// A master with no TPROXY listener still drops client QUIC, and that port really
// is accounted for — nothing waits for a reply that cannot come.
func TestAccountedBlackHolesFollowsTheRenderedRefusals(t *testing.T) {
	spec := masterSpec()
	spec.Master.BindAddress = "" // no listener resolved yet ⇒ no interception, QUIC dropped
	in := master0NATInput(t, spec)
	if !accountedUDPBlackHoles(in)[netfw.QUICPort] {
		t.Fatalf("the ruleset drops client UDP/%d, yet the check would still report it as an undeclared black hole",
			netfw.QUICPort)
	}
}

// The probe's input must be the input the ruleset was rendered from, or the ports
// it claims are refused describe a ruleset this node never applied.
func TestNATInputForMatchesTheRenderedRuleset(t *testing.T) {
	a := &agent{stateDir: t.TempDir(), role: domain.RoleMaster}
	spec := masterSpec()
	in := a.natInputFor(spec)
	if in.ClientCIDR != spec.WGServer.AddressPool {
		t.Errorf("client pool %q does not come from the spec (%q)", in.ClientCIDR, spec.WGServer.AddressPool)
	}
	if in.TProxyAddr == "" {
		t.Error("a master with a resolved bind address renders a TPROXY listener; the probe thinks it does not")
	}
	// Every declared direct destination reaches the probe. Not an equal count: the
	// list now also carries the client pool, because the routing exemptions and the
	// firewall's are rendered from one function and the pool belongs in both.
	for _, want := range spec.Master.DirectCIDRs {
		var found bool
		for _, got := range in.PrivateCIDRs {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("direct CIDR %q lost on the way to the probe: %v", want, in.PrivateCIDRs)
		}
	}
	if _, err := netfw.RenderMasterNAT(in); err != nil {
		t.Fatalf("the probe built an input the renderer rejects: %v", err)
	}
}

// A nil move machine must not panic the probe: the decision is taken after the
// pass, and the first pass of a fresh process asks before it has decided.
func TestNATInputForToleratesAnUndecidedMove(t *testing.T) {
	a := &agent{stateDir: t.TempDir(), role: domain.RoleMaster}
	if a.netnsMove != nil {
		t.Fatal("test premise: the move machine should be unset here")
	}
	if in := a.natInputFor(masterSpec()); in.NetnsGateway != "" {
		t.Errorf("an undecided move rendered as attached: %q", in.NetnsGateway)
	}
}

func master0NATInput(t *testing.T, spec domain.NodeSpec) netfw.MasterNATInput {
	t.Helper()
	a := &agent{stateDir: t.TempDir(), role: domain.RoleMaster}
	return a.natInputFor(spec)
}
