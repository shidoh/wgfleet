package netfw

import (
	"strings"
	"testing"
)

// The difference between blocking IPv6 and black-holing it is one ICMP message.
// A drop leaves the client waiting out a connect timeout on every dual-stack host
// happy eyeballs prefers — pages that load then stall, video that plays then
// freezes, a fault that reads as MTU or flakiness for days. A rejection makes the
// OS fall back to IPv4 at once.
func TestMasterV6BlockRejectsAudibly(t *testing.T) {
	out, err := RenderMasterV6Block("wg0", "fd70:c15b:d7e0::/64")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "reject with icmpv6 type admin-prohibited") {
		t.Errorf("client IPv6 is dropped, not rejected; every dual-stack site stalls:\n%s", out)
	}
	if !strings.Contains(out, `iifname "wg0" ip6 saddr fd70:c15b:d7e0::/64`) {
		t.Errorf("the rejection is not scoped to the client prefix:\n%s", out)
	}
	// A master with a public IPv6 address must not become an open router just
	// because forwarding had to be switched on for the rejection to be reachable.
	if !strings.Contains(out, "policy drop") {
		t.Errorf("the forward chain does not default to drop:\n%s", out)
	}
	// Neighbour discovery and PMTU ride on ICMPv6; dropping them breaks the link
	// rather than the routing.
	for _, want := range []string{"nd-neighbor-solicit", "nd-neighbor-advert", "packet-too-big"} {
		if !strings.Contains(out, want) {
			t.Errorf("ICMPv6 %s is not permitted:\n%s", want, out)
		}
	}
	// Atomic replace, or rules accumulate on every reconcile pass.
	if !strings.Contains(out, "delete table ip6 "+MasterV6Table) {
		t.Errorf("no atomic table replace:\n%s", out)
	}
}

func TestMasterV6BlockRefusesBadInput(t *testing.T) {
	if _, err := RenderMasterV6Block("", "fd00::/64"); err == nil {
		t.Error("an empty client interface must be refused")
	}
	if _, err := RenderMasterV6Block("wg0", "10.80.0.0/24"); err == nil {
		t.Error("an IPv4 prefix must be refused")
	}
	if _, err := RenderMasterV6Block("wg0", "nonsense"); err == nil {
		t.Error("a malformed prefix must be refused")
	}
}
