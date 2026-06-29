package config

import (
	"strings"
	"testing"
	"time"

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

func TestValidateReconcileInterval(t *testing.T) {
	for _, ok := range []time.Duration{0, 5 * time.Second, 30 * time.Second, time.Hour} {
		cfg := baseValidController()
		cfg.Fleet.ReconcileInterval = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("reconcile_interval %s rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []time.Duration{time.Second, 4 * time.Second, 2 * time.Hour} {
		cfg := baseValidController()
		cfg.Fleet.ReconcileInterval = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "reconcile_interval") {
			t.Errorf("reconcile_interval %s should be rejected, got %v", bad, err)
		}
	}
}

func TestAgentReconcileInterval(t *testing.T) {
	if got := (FleetSection{}).AgentReconcileInterval(); got != DefaultReconcileInterval {
		t.Errorf("unset: got %s, want default %s", got, DefaultReconcileInterval)
	}
	if got := (FleetSection{ReconcileInterval: 45 * time.Second}).AgentReconcileInterval(); got != 45*time.Second {
		t.Errorf("set: got %s, want 45s", got)
	}
}

func TestValidateMihomoHealthInterval(t *testing.T) {
	withInterval := func(d time.Duration) ControllerConfig {
		cfg := baseValidController()
		cfg.Fleet.Masters = []MasterConfig{{Name: "m", Mihomo: MihomoConfig{HealthInterval: d}}}
		return cfg
	}
	for _, ok := range []time.Duration{0, 5 * time.Second, 30 * time.Second, time.Hour} {
		if err := withInterval(ok).Validate(); err != nil {
			t.Errorf("health_interval %s rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []time.Duration{time.Second, 2 * time.Hour} {
		if err := withInterval(bad).Validate(); err == nil || !strings.Contains(err.Error(), "health_interval") {
			t.Errorf("health_interval %s should be rejected, got %v", bad, err)
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
			{Name: "e2", MgmtAddr: ""},             // skipped
			{Name: "e3", MgmtAddr: "10.20.25.254"}, // dup of master, skipped
			{Name: "e4", MgmtAddr: "not-an-ip"},    // skipped
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

func TestValidateExitLinkMTU(t *testing.T) {
	for _, ok := range []int{0, 1280, 1400, 1500} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", LinkMTU: ok}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("link_mtu %d rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []int{100, 1279, 1501} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", LinkMTU: bad}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "link_mtu") {
			t.Errorf("link_mtu %d should be rejected, got %v", bad, err)
		}
	}
}

func TestValidateExitWARPMTU(t *testing.T) {
	for _, ok := range []int{0, 1280, 1380, 1500} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", WARPMTU: ok}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("warp_mtu %d rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []int{100, 1279, 1501} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", WARPMTU: bad}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "warp_mtu") {
			t.Errorf("warp_mtu %d should be rejected, got %v", bad, err)
		}
	}
}

func TestValidateMgmtAddr(t *testing.T) {
	for _, ok := range []string{"", "10.20.3.20", "fd00::1"} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", MgmtAddr: ok}}
		cfg.Fleet.Masters = []MasterConfig{{Name: "m1", MgmtAddr: ok}}
		if err := cfg.Validate(); err != nil {
			t.Errorf("mgmt_addr %q rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []string{"not-an-ip", "10.20.3.20\nExecStart=/bin/evil", "10.20.3.20 evil", "host:9301"} {
		cfg := baseValidController()
		cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", MgmtAddr: bad}}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mgmt_addr") {
			t.Errorf("mgmt_addr %q should be rejected, got %v", bad, err)
		}
	}
}

func TestValidateProbeURL(t *testing.T) {
	for _, ok := range []string{"", "https://speed.cloudflare.com/__down?bytes=262144", "http://example.com/x"} {
		cfg := baseValidController()
		cfg.Fleet.EgressThroughputProbeURL = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("probe_url %q rejected unexpectedly: %v", ok, err)
		}
	}
	for _, bad := range []string{"file:///etc/passwd", "ftp://x/y", "http://", "://nohost", "169.254.169.254"} {
		cfg := baseValidController()
		cfg.Fleet.EgressThroughputProbeURL = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "egress_throughput_probe_url") {
			t.Errorf("probe_url %q should be rejected, got %v", bad, err)
		}
	}
}

func TestValidateRejectsCIDRInjection(t *testing.T) {
	// Master direct_cidrs feed the nft NAT `ip daddr != <cidr>` guards (run as root);
	// a crafted value that would inject nft syntax must be rejected before render.
	cfg := baseValidController()
	cfg.Fleet.Masters = []MasterConfig{{Name: "m1", Routing: MasterRouting{DirectCIDRs: []string{"10.0.0.0/8 ; flush ruleset"}}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "direct_cidrs") {
		t.Fatalf("expected direct_cidrs CIDR rejection, got %v", err)
	}

	// Exit address_pool feeds the exit MASQUERADE ClientCIDR — same injection vector.
	cfg = baseValidController()
	cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", AddressPool: "10.81.0.0/24 evil"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "address_pool") {
		t.Fatalf("expected address_pool CIDR rejection, got %v", err)
	}

	// Master client_awg.address_pool feeds the master NAT ClientCIDR — same vector.
	cfg = baseValidController()
	cfg.Fleet.Masters = []MasterConfig{{Name: "m1", ClientAWG: ClientAWGConfig{AddressPool: "10.80.0.0/24; flush ruleset"}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "client_awg.address_pool") {
		t.Fatalf("expected client_awg.address_pool CIDR rejection, got %v", err)
	}

	// A well-formed CIDR list still passes.
	cfg = baseValidController()
	cfg.Fleet.Masters = []MasterConfig{{Name: "m1", Routing: MasterRouting{DirectCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}}}
	cfg.Fleet.Exits = []ExitConfig{{Name: "e1", Egress: "warp", AddressPool: "10.81.0.0/24"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid CIDRs rejected: %v", err)
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
