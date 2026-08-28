package wg

import (
	"net/netip"
	"testing"
)

func TestClientULAForIsUniqueLocalStableAndPoolSpecific(t *testing.T) {
	a, err := ClientULAFor("10.80.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if a.Bits() != 64 {
		t.Errorf("prefix = %v, want a /64", a)
	}
	if got := a.Addr().As16()[0]; got != 0xfd {
		t.Errorf("prefix %v is not in fd00::/8; RFC 4193 unique-local is the only range safe to invent", a)
	}
	// Stable: the agent and the controller derive it independently and must agree.
	if b, _ := ClientULAFor("10.80.0.0/24"); a != b {
		t.Errorf("derivation is not stable: %v then %v", a, b)
	}
	// Pool-specific: two masters must not hand out the same prefix.
	if b, _ := ClientULAFor("10.90.0.0/24"); a == b {
		t.Errorf("two different pools derived the same prefix %v", a)
	}
	// Unmasked input must not change the answer.
	if b, _ := ClientULAFor("10.80.0.7/24"); a != b {
		t.Errorf("a host address in the pool changed the prefix: %v vs %v", a, b)
	}
	if _, err := ClientULAFor("fd00::/64"); err == nil {
		t.Error("an IPv6 pool must be refused")
	}
}

func TestClientV6ForCarriesTheIPv4Identity(t *testing.T) {
	prefix, err := ClientULAFor("10.80.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ClientV6For(prefix, netip.MustParseAddr("10.80.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	second, _ := ClientV6For(prefix, netip.MustParseAddr("10.80.0.3"))
	if first == second {
		t.Errorf("two clients share the v6 address %v", first)
	}
	if !prefix.Contains(first) {
		t.Errorf("%v is outside the master's prefix %v", first, prefix)
	}
	// The gateway is the pool's first host in v4 and must be so in v6 too, or the
	// client has no one to receive its ICMPv6 rejection from.
	gw, _ := ClientV6For(prefix, netip.MustParseAddr("10.80.0.1"))
	if gw == first {
		t.Errorf("the gateway and a client share %v", gw)
	}
	if _, err := ClientV6For(prefix, netip.MustParseAddr("::1")); err == nil {
		t.Error("a v6 input must be refused")
	}
}
