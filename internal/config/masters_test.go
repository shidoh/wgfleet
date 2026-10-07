package config

import (
	"strings"
	"testing"
)

// twoMasters is baseValidController with two masters and one exit — the smallest
// manifest the multi-master checks have anything to say about.
func twoMasters() ControllerConfig {
	cfg := baseValidController()
	cfg.Fleet = FleetSection{
		InterfaceAnchor: "master-xa-1",
		Masters: []MasterConfig{
			{Name: "master-xa-1", Slot: 0},
			{Name: "master-xa-2", Slot: 1},
		},
		Exits: []ExitConfig{{Name: "exit-de-1", AddressPool: "10.81.0.0/24", Egress: "direct"}},
	}
	return cfg
}

func TestValidateAcceptsTwoMasters(t *testing.T) {
	if err := twoMasters().Validate(); err != nil {
		t.Fatalf("two masters rejected: %v", err)
	}
}

func TestBaseMasterAndAnchorLabel(t *testing.T) {
	f := twoMasters().Fleet
	base, ok := f.BaseMaster()
	if !ok || base.Name != "master-xa-1" || !base.IsBase() {
		t.Fatalf("base = %q, %v", base.Name, ok)
	}
	// The anchor is a label, not a node: it survives the master it was named after.
	f.Masters = f.Masters[1:]
	if got := f.AnchorLabel(); got != "master-xa-1" {
		t.Errorf("anchor after the base master left = %q, want master-xa-1", got)
	}
	if _, ok := f.BaseMaster(); ok {
		t.Error("no master holds slot 0, so there is no base master")
	}
	// Unset, it follows the base master — a one-master manifest sets nothing.
	one := FleetSection{Masters: []MasterConfig{{Name: "master-xa-1"}}}
	if got := one.AnchorLabel(); got != "master-xa-1" {
		t.Errorf("default anchor = %q, want the base master's name", got)
	}
	if got := (FleetSection{}).AnchorLabel(); got != "" {
		t.Errorf("anchor of a fleet with no masters = %q, want empty", got)
	}
}

func TestValidateMasterFanout(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*FleetSection)
		wantFrag string
	}{
		{"two masters without an anchor label",
			func(f *FleetSection) { f.InterfaceAnchor = "" },
			`interface_anchor: "master-xa-1"`},
		{"two masters on one slot",
			func(f *FleetSection) { f.Masters[1].Slot = 0 },
			"slot 0 is taken by"},
		{"slot out of range",
			func(f *FleetSection) { f.Masters[1].Slot = 64 },
			"slot 64 out of range"},
		{"negative slot",
			func(f *FleetSection) { f.Masters[1].Slot = -1 },
			"slot -1 out of range"},
		{"exit pool too small for the highest slot",
			func(f *FleetSection) { f.Exits[0].AddressPool = "10.81.0.0/30" },
			"fleet.exits[0] (exit-de-1): address_pool 10.81.0.0/30 has no host 5"},
		{"master named like the client seed",
			func(f *FleetSection) { f.Masters[1].Name = "clients" },
			`"clients" is reserved`},
		{"exit named like the lifeline seed",
			func(f *FleetSection) { f.Exits[0].Name = "lifeline" },
			`"lifeline" is reserved`},
		{"a lone master off slot 0 with no anchor label",
			func(f *FleetSection) { f.Masters = f.Masters[1:]; f.InterfaceAnchor = "" },
			"interface_anchor"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := twoMasters()
			c.mutate(&cfg.Fleet)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), c.wantFrag) {
				t.Fatalf("want an error containing %q, got %v", c.wantFrag, err)
			}
		})
	}
}

// A one-master manifest that sets neither key is exactly as valid as before.
func TestValidateOneMasterNeedsNoNewKeys(t *testing.T) {
	cfg := baseValidController()
	cfg.Fleet.Masters = []MasterConfig{{Name: "master-xa-1"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("one master rejected: %v", err)
	}
}
