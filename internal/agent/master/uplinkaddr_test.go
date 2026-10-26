package master

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
)

func TestMasterFirewallCountsHandshakesOnTheUplinkAddress(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)
	pl := firewallPlanner{
		path:       paths.FirewallNFT,
		loaded:     func() bool { return false },
		uplinkAddr: func() netip.Addr { return netip.MustParseAddr("192.0.2.10") },
	}
	_, _ = reconcile.NewEngine(nil, pl).Reconcile(context.Background(), spec, reconcile.ModeApply)
	data, err := os.ReadFile(paths.FirewallNFT)
	if err != nil {
		t.Fatalf("firewall ruleset not written: %v", err)
	}
	if !strings.Contains(string(data), `ip saddr 192.0.2.10 tcp flags & (syn | ack) == syn counter name "uplink_syn_out"`) {
		t.Errorf("master firewall does not count SYNs from the uplink address:\n%s", data)
	}
}

// No address, no counters, and still a firewall: the measurement is optional,
// the drop policy is not.
func TestMasterFirewallWithoutAnUplinkAddress(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)
	pl := firewallPlanner{
		path:       paths.FirewallNFT,
		loaded:     func() bool { return false },
		uplinkAddr: func() netip.Addr { return netip.Addr{} },
	}
	_, _ = reconcile.NewEngine(nil, pl).Reconcile(context.Background(), spec, reconcile.ModeApply)
	data, err := os.ReadFile(paths.FirewallNFT)
	if err != nil {
		t.Fatalf("firewall ruleset not written: %v", err)
	}
	if strings.Contains(string(data), "uplink_") || !strings.Contains(string(data), "policy drop;") {
		t.Errorf("want the firewall without uplink counters:\n%s", data)
	}
}

// The real detector, wherever this test runs: it either finds an IPv4 source or
// says it found none. It never returns an IPv6 address the renderer would skip
// anyway, nor a loopback that would count nothing.
func TestDetectUplinkAddr(t *testing.T) {
	a := detectUplinkAddr()
	if !a.IsValid() {
		t.Skip("no IPv4 default route on this box")
	}
	if !a.Is4() || a.IsLoopback() || a.IsUnspecified() {
		t.Fatalf("detectUplinkAddr() = %v, want a routable IPv4 source", a)
	}
}
