package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/wg"
)

// newExitInitiatedFleet is one master with a public address and one AWG exit that
// starts the master↔exit flow itself — the shape validateExitInitiated accepts.
func newExitInitiatedFleet() FleetSection {
	return FleetSection{
		Masters: []MasterConfig{{Name: "m", PublicIP: "192.0.2.10"}},
		Exits: []ExitConfig{{
			Name: "e",
			Transports: TransportsConfig{
				AWG: AWGTransportConfig{Enabled: true, ExitInitiated: true},
			},
		}},
	}
}

func TestValidateExitInitiatedAcceptsTheSupportedShape(t *testing.T) {
	cases := map[string]func(f *FleetSection){
		"awg only":                  func(*FleetSection) {},
		"no transport section":      func(f *FleetSection) { f.Exits[0].Transports.AWG.Enabled = false },
		"dual transport":            func(f *FleetSection) { f.Exits[0].Transports.Reality.Enabled = true },
		"master port override":      func(f *FleetSection) { f.Exits[0].Transports.AWG.MasterPort = 41234 },
		"master address is a name":  func(f *FleetSection) { f.Masters[0].PublicIP = "master.example.net" },
		"master address left empty": func(f *FleetSection) { f.Masters[0].PublicIP = "" },
		"second master with a public address": func(f *FleetSection) {
			f.InterfaceAnchor = "m"
			f.Masters = append(f.Masters, MasterConfig{Name: "m2", Slot: 1, PublicIP: "192.0.2.11"})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fleet := newExitInitiatedFleet()
			mutate(&fleet)
			if errs := (ControllerConfig{Fleet: fleet}).validateExitInitiated(); len(errs) != 0 {
				t.Fatalf("validateExitInitiated() = %v, want no errors", errs)
			}
		})
	}
}

func TestValidateExitInitiatedRejects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(f *FleetSection)
		wantFrag string
	}{
		{
			name: "reality only",
			mutate: func(f *FleetSection) {
				f.Exits[0].Transports.AWG.Enabled = false
				f.Exits[0].Transports.Reality.Enabled = true
			},
			wantFrag: "exit_initiated needs the awg transport",
		},
		{
			name: "master port without the flag",
			mutate: func(f *FleetSection) {
				f.Exits[0].Transports.AWG.ExitInitiated = false
				f.Exits[0].Transports.AWG.MasterPort = 41234
			},
			wantFrag: "master_port is set but exit_initiated is off",
		},
		{
			name:     "master port below 1024",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.AWG.MasterPort = 53 },
			wantFrag: "master_port 53 out of range",
		},
		{
			name:     "master port above 65535",
			mutate:   func(f *FleetSection) { f.Exits[0].Transports.AWG.MasterPort = 70000 },
			wantFrag: "master_port 70000 out of range",
		},
		{
			name: "second master the exit could not knock on",
			mutate: func(f *FleetSection) {
				f.InterfaceAnchor = "m"
				f.Masters = append(f.Masters, MasterConfig{Name: "m2", Slot: 1, PublicIP: "172.16.99.11"})
			},
			wantFrag: "is not a public IPv4 address",
		},
		{
			name:     "no master at all",
			mutate:   func(f *FleetSection) { f.Masters = nil },
			wantFrag: "needs a master",
		},
		{
			// The exit would knock on an address the internet cannot reach, and the
			// master's gate — closed until the exit is heard — would never open.
			name:     "master address is private",
			mutate:   func(f *FleetSection) { f.Masters[0].PublicIP = "172.16.99.10" },
			wantFrag: "is not a public IPv4 address",
		},
		{
			name:     "master address is IPv6",
			mutate:   func(f *FleetSection) { f.Masters[0].PublicIP = "2001:db8::1" },
			wantFrag: "is not a public IPv4 address",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fleet := newExitInitiatedFleet()
			tc.mutate(&fleet)
			errs := (ControllerConfig{Fleet: fleet}).validateExitInitiated()
			for _, err := range errs {
				if strings.Contains(err.Error(), tc.wantFrag) {
					return
				}
			}
			t.Fatalf("validateExitInitiated() = %v, want an error containing %q", errs, tc.wantFrag)
		})
	}
}

func TestAWGMasterPort(t *testing.T) {
	e := ExitConfig{Name: "exit-a"}
	if got, want := e.AWGMasterPort("m", true), wg.MasterPortFor("m", "exit-a"); got != want {
		t.Fatalf("derived AWGMasterPort = %d, want %d", got, want)
	}
	e.Transports.AWG.MasterPort = 41234
	if got := e.AWGMasterPort("m", true); got != 41234 {
		t.Fatalf("override AWGMasterPort = %d, want 41234", got)
	}
}

// The operator's master_port is the recovery lever for ONE poisoned flow. Applied
// to every master it would also move the healthy ones.
func TestMasterPortPinIsTheBaseMastersAlone(t *testing.T) {
	e := ExitConfig{Name: "exit-de-1", Transports: TransportsConfig{AWG: AWGTransportConfig{MasterPort: 41234}}}
	if got := e.AWGMasterPort("master-xa-1", true); got != 41234 {
		t.Errorf("base master port = %d, want the pin", got)
	}
	if got := e.AWGMasterPort("master-xa-2", false); got != wg.MasterPortFor("master-xa-2", "exit-de-1") {
		t.Errorf("another master's port = %d, want its own derivation", got)
	}
}
