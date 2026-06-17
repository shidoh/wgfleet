package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/routing"
)

func TestValidateZeroTierNetworkID(t *testing.T) {
	valid := []string{"", "8056c2e21c000001", "ABCDEF0123456789"}
	for _, id := range valid {
		cfg := baseValidController()
		cfg.Fleet.ZeroTierNetwork = id
		if err := cfg.Validate(); err != nil {
			t.Errorf("zerotier id %q rejected unexpectedly: %v", id, err)
		}
	}

	invalid := []string{
		"not-hex",
		"8056c2e21c00000",       // 15 chars
		"8056c2e21c0000011",     // 17 chars
		"8056c2e2; rm -rf /",    // injection attempt
		"8056c2e21c000001 evil", // trailing command
	}
	for _, id := range invalid {
		cfg := baseValidController()
		cfg.Fleet.ZeroTierNetwork = id
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "zerotier_network") {
			t.Errorf("zerotier id %q should be rejected, got %v", id, err)
		}
	}
}

func TestValidateRejectsMultiMaster(t *testing.T) {
	cfg := baseValidController()
	cfg.Fleet.Masters = []MasterConfig{{Name: "m1"}, {Name: "m2"}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "multi-master") {
		t.Fatalf("expected multi-master rejection, got %v", err)
	}

	// One master is fine.
	cfg.Fleet.Masters = []MasterConfig{{Name: "m1"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("single master rejected unexpectedly: %v", err)
	}
}

func TestValidateMgmtSubnet(t *testing.T) {
	for _, ok := range []string{"", "10.20.0.0/16", "10.147.0.0/16", "fd00::/8"} {
		cfg := baseValidController()
		cfg.Fleet.MgmtSubnet = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("mgmt_subnet %q rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []string{"10.20.0.0", "not-a-cidr", "10.0.0.0/33"} {
		cfg := baseValidController()
		cfg.Fleet.MgmtSubnet = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mgmt_subnet") {
			t.Errorf("mgmt_subnet %q should be rejected, got %v", bad, err)
		}
	}
}

func TestValidateMgmtOverlayMSS(t *testing.T) {
	for _, ok := range []int{0, 536, 1240, 1460} {
		cfg := baseValidController()
		cfg.Fleet.MgmtOverlayMSS = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("mgmt_overlay_mss %d rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []int{1, 535, 1461} {
		cfg := baseValidController()
		cfg.Fleet.MgmtOverlayMSS = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mgmt_overlay_mss") {
			t.Errorf("mgmt_overlay_mss %d should be rejected, got %v", bad, err)
		}
	}
}

func TestMgmtCIDRs(t *testing.T) {
	// Explicit subnet wins and is normalized (host bits masked).
	f := FleetSection{MgmtSubnet: "10.20.10.5/16"}
	if got := f.MgmtCIDRs(); len(got) != 1 || got[0] != "10.20.0.0/16" {
		t.Errorf("explicit subnet: got %v, want [10.20.0.0/16]", got)
	}

	// No subnet ⇒ derive /32 host routes from every node's mgmt_addr, deduped,
	// masters before exits; unparseable/empty addrs are skipped.
	f = FleetSection{
		Masters: []MasterConfig{{Name: "m", MgmtAddr: "10.20.25.254"}},
		Exits: []ExitConfig{
			{Name: "e1", MgmtAddr: "10.20.25.1"},
			{Name: "e2", MgmtAddr: ""},              // skipped
			{Name: "e3", MgmtAddr: "10.20.25.254"}, // dup of master, skipped
			{Name: "e4", MgmtAddr: "not-an-ip"},     // skipped
		},
	}
	got := f.MgmtCIDRs()
	want := []string{"10.20.25.254/32", "10.20.25.1/32"}
	if len(got) != len(want) {
		t.Fatalf("derived CIDRs: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("derived CIDRs[%d]: got %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}

	// Nothing to derive ⇒ nil (callers treat as "unset").
	if got := (FleetSection{}).MgmtCIDRs(); got != nil {
		t.Errorf("empty fleet: got %v, want nil", got)
	}
}

func TestValidateDirectCIDRsCap(t *testing.T) {
	over := make([]string, routing.MaxDirectCIDRs+1)
	for i := range over {
		over[i] = "10.0.0.0/8"
	}
	cfg := baseValidController()
	cfg.Fleet.Masters = []MasterConfig{{Name: "m1", Routing: MasterRouting{DirectCIDRs: over}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "direct_cidrs") {
		t.Fatalf("expected direct_cidrs cap error, got %v", err)
	}

	// At the cap is fine.
	cfg.Fleet.Masters[0].Routing.DirectCIDRs = over[:routing.MaxDirectCIDRs]
	if err := cfg.Validate(); err != nil {
		t.Fatalf("direct_cidrs at cap rejected: %v", err)
	}
}
