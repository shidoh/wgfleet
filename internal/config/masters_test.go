package config

import (
	"fmt"
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
		{"master named like the lifeline seed",
			func(f *FleetSection) { f.Masters[1].Name = "lifeline" },
			`fleet.masters[1]: name "lifeline" is reserved`},
		{"exit named like the client seed",
			func(f *FleetSection) { f.Exits[0].Name = "clients" },
			`fleet.exits[0]: name "clients" is reserved`},
		{"anchor label named like the client seed",
			func(f *FleetSection) { f.InterfaceAnchor = "clients" },
			`fleet.interface_anchor: "clients" is reserved`},
		{"anchor label named like the lifeline seed",
			func(f *FleetSection) { f.InterfaceAnchor = "lifeline" },
			`fleet.interface_anchor: "lifeline" is reserved`},
		{"anchor label with a space in it",
			func(f *FleetSection) { f.InterfaceAnchor = "master ru 1" },
			"fleet.interface_anchor"},
		{"anchor label with a tab in it",
			func(f *FleetSection) { f.InterfaceAnchor = "master\tru-1" },
			"fleet.interface_anchor"},
		{"anchor label with the seed separator in it",
			func(f *FleetSection) { f.InterfaceAnchor = "master|xa-1" },
			"fleet.interface_anchor"},
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

// directCIDRs is n distinct, valid direct CIDRs.
func directCIDRs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	return out
}

// An exit's direct rules are the base master's direct_cidrs, the management
// CIDRs and one host route per other master, each on its own priority. Past the
// cap a policy-routed exit cannot apply its routing at all. That is said, loudly
// — and never refused: such a manifest starts today (a fleet of direct-egress
// exits runs fine over the count), so it has to start after the upgrade too.
func TestExitDirectRuleWarnings(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*FleetSection)
		wantWarn string
	}{
		{"at the cap: 78 direct + 1 mgmt subnet + 1 other master",
			func(f *FleetSection) {
				f.MgmtSubnet = "10.200.0.0/24"
				f.Masters[0].Routing.DirectCIDRs = directCIDRs(78)
			}, ""},
		{"one over, with a mgmt subnet",
			func(f *FleetSection) {
				f.MgmtSubnet = "10.200.0.0/24"
				f.Masters[0].Routing.DirectCIDRs = directCIDRs(79)
			}, "81 direct rules"},
		{"one over, from per-node mgmt addresses",
			func(f *FleetSection) {
				f.Masters[0].MgmtAddr, f.Masters[1].MgmtAddr, f.Exits[0].MgmtAddr = "10.200.0.1", "10.200.0.2", "10.200.0.3"
				f.Masters[0].Routing.DirectCIDRs = directCIDRs(77)
			}, "81 direct rules"},
		// What the exit renders is de-duplicated; a management subnet that is also a
		// direct CIDR costs one priority, not two.
		{"a mgmt subnet already in direct_cidrs is counted once",
			func(f *FleetSection) {
				f.MgmtSubnet = "10.5.0.0/16"
				f.Masters[0].Routing.DirectCIDRs = directCIDRs(79)
			}, ""},
		// Only the base master's list reaches the exits.
		{"another master's long list is not the exits' business",
			func(f *FleetSection) {
				f.MgmtSubnet = "10.200.0.0/24"
				f.Masters[1].Routing.DirectCIDRs = directCIDRs(80)
			}, ""},
		{"one master, over the cap with its mgmt subnet",
			func(f *FleetSection) {
				f.Masters = f.Masters[:1]
				f.InterfaceAnchor = ""
				f.MgmtSubnet = "10.200.0.0/24"
				f.Masters[0].Routing.DirectCIDRs = directCIDRs(80)
			}, "81 direct rules"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := twoMasters()
			c.mutate(&cfg.Fleet)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("the manifest was refused; the count is a warning, never a load failure: %v", err)
			}
			warns := ExitDirectRuleWarnings(cfg)
			switch {
			case c.wantWarn == "" && len(warns) != 0:
				t.Fatalf("warned: %q", warns)
			case c.wantWarn == "":
				return
			case len(warns) != 1 || !strings.Contains(warns[0], c.wantWarn):
				t.Fatalf("want one warning containing %q, got %q", c.wantWarn, warns)
			}
			for _, cause := range []string{"routing.direct_cidrs", "fleet.mgmt_subnet", "80"} {
				if !strings.Contains(warns[0], cause) {
					t.Errorf("the warning does not name %q: %s", cause, warns[0])
				}
			}
		})
	}
	// No exits: nothing is rendered a direct rule.
	cfg := twoMasters()
	cfg.Fleet.Exits = nil
	cfg.Fleet.Masters[0].Routing.DirectCIDRs = directCIDRs(80)
	if warns := ExitDirectRuleWarnings(cfg); len(warns) != 0 {
		t.Errorf("warned about a fleet with no exits: %q", warns)
	}
}

func TestMasterDNSFor(t *testing.T) {
	own := DNSConfig{Allowlist: []string{"own.example"}}
	shared := DNSConfig{Allowlist: []string{"shared.example"}}
	m := MasterConfig{Name: "master-xa-1", DNS: own}

	// One master and no fleet-level block: its own dns is what it gets.
	if got := (FleetSection{}).MasterDNSFor(m); got.Allowlist[0] != "own.example" {
		t.Errorf("without fleet.master_dns = %v, want the master's own dns", got.Allowlist)
	}
	// fleet.master_dns is every master's resolver configuration.
	f := FleetSection{MasterDNS: shared}
	for _, m := range []MasterConfig{{Name: "master-xa-1"}, {Name: "master-xa-2", Slot: 1}} {
		if got := f.MasterDNSFor(m); len(got.Allowlist) != 1 || got.Allowlist[0] != "shared.example" {
			t.Errorf("%s: dns = %v, want fleet.master_dns", m.Name, got.Allowlist)
		}
	}
}

func TestValidateMasterDNSIsOneForAllMasters(t *testing.T) {
	dns := DNSConfig{Overrides: map[string]any{"conditional": map[string]any{}}}
	cases := []struct {
		name     string
		mutate   func(*FleetSection)
		wantFrag string // empty ⇒ must validate
	}{
		{"several masters share fleet.master_dns",
			func(f *FleetSection) { f.MasterDNS = dns }, ""},
		{"several masters, one with its own dns",
			func(f *FleetSection) { f.Masters[0].DNS = dns },
			"fleet.masters[0] (master-xa-1): dns is per master; with several masters set fleet.master_dns"},
		{"fleet.master_dns and a master's own dns",
			func(f *FleetSection) { f.MasterDNS = dns; f.Masters[1].DNS = dns },
			"fleet.masters[1] (master-xa-2): dns is set alongside fleet.master_dns"},
		{"one master keeps its own dns",
			func(f *FleetSection) { f.Masters = f.Masters[:1]; f.Masters[0].DNS = dns }, ""},
		{"one master with both",
			func(f *FleetSection) { f.Masters = f.Masters[:1]; f.Masters[0].DNS = dns; f.MasterDNS = dns },
			"fleet.masters[0] (master-xa-1): dns is set alongside fleet.master_dns"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := twoMasters()
			tc.mutate(&cfg.Fleet)
			err := cfg.Validate()
			switch {
			case tc.wantFrag == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case tc.wantFrag != "" && (err == nil || !strings.Contains(err.Error(), tc.wantFrag)):
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantFrag)
			}
		})
	}
}
