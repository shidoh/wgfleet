package netfw

import (
	"strings"
	"testing"
)

func TestRenderMasterNAT(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table ip wgfleet_master",
		`iifname "wg0" ip daddr != 10.0.0.0/8 ip daddr != 172.16.0.0/12 ip daddr != 192.168.0.0/16 udp dport 443 drop`,
		`ip protocol tcp dnat to 10.80.0.1:7895`,
		// Masquerade on every egress except back into the client interface, so the
		// overlay/DNS path is NAT'd too (not only the public uplink).
		`ip saddr 10.80.0.0/24 oifname != "wg0" masquerade`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master NAT missing %q:\n%s", want, out)
		}
	}
}

func TestRenderMasterNATRequiresFields(t *testing.T) {
	if _, err := RenderMasterNAT(MasterNATInput{ClientInterface: "wg0"}); err == nil {
		t.Fatal("expected error for missing CIDR/redir")
	}
	// Egress interface is no longer required — masquerade covers all non-client
	// egress — so the core three fields are sufficient.
	if _, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.80.0.0/24", RedirAddr: "10.80.0.1:7895",
	}); err != nil {
		t.Fatalf("unexpected error with the required fields present: %v", err)
	}
}
