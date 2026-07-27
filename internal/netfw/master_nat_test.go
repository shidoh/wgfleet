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
		// Atomic replace (delete-first) so re-applies don't accumulate duplicate
		// DNAT/masquerade rules or leave stale ones from an older binary.
		"delete table ip wgfleet_master",
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

func TestRenderMasterNATEgressLeakGuard(t *testing.T) {
	// The master masquerades its client pool just as an exit does, so it inherits the
	// same failure: a packet conntrack cannot place carries no NAT binding and would
	// leave with a client's private source, after which upstream returns replies to
	// that address and conntrack rewrites the source port to resolve the collision.
	// The guard asserts the outcome — nothing leaves with a pool source — and must run
	// AFTER srcnat so translated packets have already stopped matching.
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"chain egress_leak_guard",
		"type filter hook postrouting priority srcnat + 10",
		// Mirrors the masquerade's scope exactly, or it would either miss the leak or
		// fire on traffic that was translated correctly.
		`ip saddr 10.80.0.0/24 oifname != "wg0" counter drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master egress leak guard missing %q:\n%s", want, out)
		}
	}

	// The guard must use the CANONICAL pool, never the raw operator string — this
	// ruleset is applied as root, so an unparsed CIDR here would be an injection point
	// exactly as it is for the masquerade.
	out2, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.7/24",
		RedirAddr:       "10.80.0.1:7895",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, `ip saddr 10.80.0.0/24 oifname != "wg0" counter drop`) {
		t.Errorf("guard did not canonicalize the client pool:\n%s", out2)
	}
}

func TestRenderMasterNATRejectsCIDRInjection(t *testing.T) {
	// A crafted direct-CIDR value must never reach the rendered nft script verbatim:
	// it is parsed and re-emitted canonically, so injection attempts fail the render.
	if _, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"10.0.0.0/8 ; flush ruleset"},
	}); err == nil {
		t.Fatal("expected error for nft-injecting private CIDR")
	}
	// A bad client CIDR is likewise rejected.
	if _, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "not-a-cidr",
		RedirAddr:       "10.80.0.1:7895",
	}); err == nil {
		t.Fatal("expected error for malformed client CIDR")
	}
}

func TestRenderMasterNATCanonicalizesCIDRs(t *testing.T) {
	// A host-bit-dirty CIDR is masked to its canonical network form in the output.
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.7/24", // host bits set
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"10.1.2.3/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ip saddr 10.80.0.0/24") {
		t.Errorf("client CIDR not canonicalized to 10.80.0.0/24:\n%s", out)
	}
	if !strings.Contains(out, "ip daddr != 10.0.0.0/8") {
		t.Errorf("private CIDR not canonicalized to 10.0.0.0/8:\n%s", out)
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
