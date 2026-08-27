package domain

import (
	"net/netip"
	"strings"
	"testing"
)

// The list is only correct if the right addresses land on the right side of it,
// so that is what the tests assert — not the shape of the expansion. A hand-read
// list of forty CIDRs proves nothing; membership does.
func TestExpandAllowedIPsRoutesTheRightAddresses(t *testing.T) {
	got, err := ExpandAllowedIPs(
		[]string{"172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"},
		[]string{"10.0.0.0/8", "172.19.57.0/24", "172.29.0.0/16"},
	)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	in := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, c := range got {
			if netip.MustParsePrefix(c).Contains(a) {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		addr, why string
		want      bool
	}{
		{"172.26.1.100", "a home service on another LAN subnet", false},
		{"172.18.3.199", "the client's own LAN", false},
		{"192.168.1.1", "the most common home router", false},
		{"100.100.0.1", "carrier-grade NAT", false},
		{"169.254.1.1", "link-local", false},
		{"10.200.99.1", "a work resolver reached through the tunnel", true},
		{"10.0.163.5", "a work subnet inside the broad 10/8", true},
		{"172.19.57.10", "a work subnet re-added inside an excluded range", true},
		{"172.29.3.10", "the management overlay", true},
		{"8.8.8.8", "the public internet", true},
		{"198.51.100.108", "a public address that happens to be at home", true},
	} {
		if in(tc.addr) != tc.want {
			t.Errorf("%s (%s): in tunnel = %v, want %v", tc.addr, tc.why, in(tc.addr), tc.want)
		}
	}
}

// Nothing excluded ⇒ the default route, not a 40-entry expansion of it.
func TestExpandAllowedIPsWithoutExclusionsIsTheDefaultRoute(t *testing.T) {
	got, err := ExpandAllowedIPs(nil, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "0.0.0.0/0" {
		t.Fatalf("got %v, want [0.0.0.0/0]", got)
	}
}

// The expansion must be byte-stable: an unstable list would rewrite every client
// config on every render.
func TestExpandAllowedIPsIsStable(t *testing.T) {
	args := func() ([]string, []string) {
		return []string{"192.168.0.0/16", "172.16.0.0/12"}, []string{"172.19.57.0/24"}
	}
	e1, r1 := args()
	a, err := ExpandAllowedIPs(e1, r1)
	if err != nil {
		t.Fatal(err)
	}
	e2, r2 := args()
	b, err := ExpandAllowedIPs(e2, r2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("expansion is not stable:\n%v\n%v", a, b)
	}
}

// A minimal cover, not a pile of /32s: excluding one half of the space must
// leave exactly the other half.
func TestExpandAllowedIPsIsMinimal(t *testing.T) {
	got, err := ExpandAllowedIPs([]string{"128.0.0.0/1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "0.0.0.0/1" {
		t.Fatalf("got %v, want [0.0.0.0/1]", got)
	}
}

func TestExpandAllowedIPsRejectsBadInput(t *testing.T) {
	if _, err := ExpandAllowedIPs([]string{"nonsense"}, nil); err == nil {
		t.Error("a malformed CIDR was accepted")
	}
	// An IPv6 entry would silently do nothing on an IPv4-only data plane.
	if _, err := ExpandAllowedIPs([]string{"fd00::/8"}, nil); err == nil {
		t.Error("an IPv6 exclusion was accepted")
	}
}
