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
