package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestWARPIPFamilyFor(t *testing.T) {
	cases := []struct {
		fleet, exit string
		want        domain.WARPIPFamily
	}{
		{"", "", domain.WARPIPFamilyAuto},
		{"ipv6", "", domain.WARPIPFamilyIPv6},
		{"ipv6", "ipv4", domain.WARPIPFamilyIPv4},
		{"", "auto", domain.WARPIPFamilyAuto},
	}
	for _, c := range cases {
		f := FleetSection{WARPIPFamily: c.fleet}
		if got := f.WARPIPFamilyFor(ExitConfig{WARPIPFamily: c.exit}); got != c.want {
			t.Errorf("fleet %q, exit %q: %q, want %q", c.fleet, c.exit, got, c.want)
		}
	}
}

func TestValidateWARPIPFamily(t *testing.T) {
	for _, ok := range []string{"", "auto", "ipv4", "ipv6"} {
		cfg := baseValidController()
		cfg.Fleet.WARPIPFamily = ok
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", WARPIPFamily: ok}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("warp_ip_family %q rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []string{"v4", "IPv4", "both"} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", WARPIPFamily: bad}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "warp_ip_family") {
			t.Errorf("exit warp_ip_family %q should be rejected, got %v", bad, err)
		}
		cfg = baseValidController()
		cfg.Fleet.WARPIPFamily = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "warp_ip_family") {
			t.Errorf("fleet warp_ip_family %q should be rejected, got %v", bad, err)
		}
	}
}
