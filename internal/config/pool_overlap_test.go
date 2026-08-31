package config

import (
	"strings"
	"testing"
)

// Exit pools were never checked against each other or against a master's client
// pool — only master↔master was, and only for the multi-master fleet the config
// rejects one function away. So the one topology that actually exists went
// unvalidated. Two exits sharing a pool both hand the master TunnelIP .2; mihomo
// builds two proxies on the same tunnel address and the second silently misroutes.
// That is intermittent, per-destination, and very hard to attribute to a manifest.
func TestOverlappingAddressPoolsAreRejected(t *testing.T) {
	cases := []struct{ name, a, b, want string }{
		{"two exits share a pool", "10.81.0.0/24", "10.81.0.0/24", "overlaps"},
		{"one exit pool contains another", "10.81.0.0/16", "10.81.5.0/24", "overlaps"},
		{"disjoint exits are fine", "10.81.0.0/24", "10.82.0.0/24", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ControllerConfig{}
			cfg.Fleet.Exits = []ExitConfig{
				{Name: "e1", Egress: "warp", AddressPool: tc.a},
				{Name: "e2", Egress: "warp", AddressPool: tc.b},
			}
			errs := validateAddressPoolsDisjoint(cfg.Fleet)
			switch {
			case tc.want == "" && len(errs) != 0:
				t.Errorf("disjoint pools rejected: %v", errs)
			case tc.want != "" && len(errs) == 0:
				t.Errorf("overlapping pools accepted (%s vs %s)", tc.a, tc.b)
			case tc.want != "" && !strings.Contains(errs[0].Error(), tc.want):
				t.Errorf("error does not say what is wrong: %v", errs[0])
			}
		})
	}
}

// An exit pool overlapping the master's CLIENT pool breaks the exit's masquerade
// scope — the exit cannot tell a client address from one of its own.
func TestExitPoolOverlappingTheMasterClientPoolIsRejected(t *testing.T) {
	cfg := ControllerConfig{}
	cfg.Fleet.Masters = []MasterConfig{{
		Name: "m", ClientAWG: ClientAWGConfig{AddressPool: "10.80.0.0/24"},
	}}
	cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", AddressPool: "10.80.0.0/24"}}

	if errs := validateAddressPoolsDisjoint(cfg.Fleet); len(errs) == 0 {
		t.Fatal("an exit pool identical to the master's client pool was accepted")
	}
}
