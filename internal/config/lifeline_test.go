package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// newLifelineFleet builds a minimal fleet with one managed master and one exit
// carrying a valid lifeline section, matching the shape validateLifeline expects:
// a master pool the lifeline pool must be at least as large as, and an exit whose
// own listen port and firewall the lifeline port must avoid.
func newLifelineFleet() FleetSection {
	managed := true
	return FleetSection{
		Masters: []MasterConfig{{
			Name:      "m",
			ClientAWG: ClientAWGConfig{Managed: &managed, AddressPool: "10.80.0.0/24"},
		}},
		Exits: []ExitConfig{{
			Name:        "e",
			AddressPool: "10.90.0.0/24",
			Egress:      "direct",
			ListenPort:  51820,
			Lifeline: &LifelineConfig{
				ListenPort:  51821,
				AddressPool: "10.98.77.0/24",
				DNS:         []string{"1.1.1.1"},
			},
		}},
	}
}

func TestValidateLifeline(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(f *FleetSection)
		wantFrag string
	}{
		{
			name:     "port zero",
			mutate:   func(f *FleetSection) { f.Exits[0].Lifeline.ListenPort = 0 },
			wantFrag: "lifeline.listen_port",
		},
		{
			name:     "port equals exit listen port",
			mutate:   func(f *FleetSection) { f.Exits[0].Lifeline.ListenPort = 51820 },
			wantFrag: "equals the exit listen_port",
		},
		{
			name: "port already public",
			mutate: func(f *FleetSection) {
				f.Exits[0].Firewall.PublicUDPPorts = []int{51821}
			},
			wantFrag: "already listed in firewall.public_udp_ports",
		},
		{
			name:     "pool empty",
			mutate:   func(f *FleetSection) { f.Exits[0].Lifeline.AddressPool = "" },
			wantFrag: "lifeline.address_pool is required",
		},
		{
			name:     "pool narrower than master pool",
			mutate:   func(f *FleetSection) { f.Exits[0].Lifeline.AddressPool = "10.80.0.0/25" },
			wantFrag: "must be at least as large as",
		},
		{
			name:     "egress bogus",
			mutate:   func(f *FleetSection) { f.Exits[0].Lifeline.Egress = "bogus" },
			wantFrag: "lifeline.egress",
		},
		{
			name: "egress warp not in exit's chain",
			mutate: func(f *FleetSection) {
				f.Exits[0].Lifeline.Egress = "warp"
				f.Exits[0].Egress = "direct"
				f.Exits[0].EgressFallback = nil
			},
			wantFrag: "WARP is not in this exit's egress chain",
		},
		{
			name: "dns empty without dns_filter",
			mutate: func(f *FleetSection) {
				f.Exits[0].Lifeline.DNS = nil
				f.Exits[0].DNSFilter = false
			},
			wantFrag: "lifeline.dns is required",
		},
		{
			name: "master client_awg not managed",
			mutate: func(f *FleetSection) {
				f.Masters[0].ClientAWG.Managed = nil
			},
			wantFrag: "client_awg.managed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fleet := newLifelineFleet()
			tc.mutate(&fleet)
			c := ControllerConfig{Fleet: fleet}
			errs := c.validateLifeline()
			if len(errs) == 0 {
				t.Fatalf("validateLifeline() returned no errors, want one containing %q", tc.wantFrag)
			}
			var found bool
			for _, err := range errs {
				if strings.Contains(err.Error(), tc.wantFrag) {
					found = true
				}
			}
			if !found {
				t.Errorf("validateLifeline() = %v, want an error containing %q", errs, tc.wantFrag)
			}
		})
	}
}

// A lifeline pool that overlaps the master's client pool is caught by
// validateAddressPoolsDisjoint (the fleet-wide pool checker), not validateLifeline
// itself — the same split every other pool already follows.
func TestLifelinePoolOverlapsMasterPool(t *testing.T) {
	fleet := newLifelineFleet()
	fleet.Exits[0].Lifeline.AddressPool = "10.80.0.0/24" // identical to the master's client pool
	errs := validateAddressPoolsDisjoint(fleet)
	if len(errs) == 0 {
		t.Fatal("a lifeline pool overlapping the master pool was accepted")
	}
	var found bool
	for _, err := range errs {
		if strings.Contains(err.Error(), "overlaps") && strings.Contains(err.Error(), "lifeline.address_pool") {
			found = true
		}
	}
	if !found {
		t.Errorf("validateAddressPoolsDisjoint() = %v, want an overlap naming lifeline.address_pool", errs)
	}
}

func TestValidateLifelineAcceptsAValidConfig(t *testing.T) {
	fleet := newLifelineFleet()
	c := ControllerConfig{Fleet: fleet}
	if errs := c.validateLifeline(); len(errs) != 0 {
		t.Errorf("validateLifeline() = %v, want no errors for a valid lifeline config", errs)
	}
}

func TestLifelineEnabled(t *testing.T) {
	if (ExitConfig{}).LifelineEnabled() {
		t.Error("LifelineEnabled() = true for an exit with no lifeline section")
	}
	e := ExitConfig{Lifeline: &LifelineConfig{}}
	if !e.LifelineEnabled() {
		t.Error("LifelineEnabled() = false for an exit with a lifeline section")
	}
}

func TestLifelineResolvedEgress(t *testing.T) {
	if got := (LifelineConfig{}).ResolvedEgress(); got != domain.EgressDirect {
		t.Errorf("ResolvedEgress() for an empty egress = %q, want %q", got, domain.EgressDirect)
	}
	if got := (LifelineConfig{Egress: " WARP "}).ResolvedEgress(); got != domain.EgressWARP {
		t.Errorf("ResolvedEgress() = %q, want %q", got, domain.EgressWARP)
	}
}
