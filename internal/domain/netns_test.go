package domain

import "testing"

// The default has to be "move". A switch that defaults to off is a fix that does
// not reach anyone who upgrades by swapping the binary — which is how this fleet's
// testers upgrade. Safety comes from the preconditions and the automatic revert,
// not from leaving the feature dormant.
func TestNetnsWantedDefaultsToMoving(t *testing.T) {
	cases := []struct {
		value      string
		wantMove   bool
		wantCanary string
	}{
		{"", true, ""},
		{"auto", true, ""},
		{"off", false, ""},
		{"10.73.0.99/32", true, "10.73.0.99/32"},
	}
	for _, tc := range cases {
		move, canary := MasterSpec{ClientViaNetns: tc.value}.NetnsWanted()
		if move != tc.wantMove || canary != tc.wantCanary {
			t.Errorf("%q: got (%v, %q), want (%v, %q)", tc.value, move, canary, tc.wantMove, tc.wantCanary)
		}
	}
}

// The link must never default into 10/8: on this fleet that range is routed to
// the corporate tunnel, declared direct, pulled into every client's AllowedIPs,
// and already carved into a /24 per exit.
func TestNetnsLinkDefaultsOutsideThePrivateRanges(t *testing.T) {
	got := MasterSpec{}.NetnsLinkCIDR()
	if got != NetnsDefaultCIDR {
		t.Fatalf("default link = %q, want %q", got, NetnsDefaultCIDR)
	}
	for _, bad := range []string{"10.", "172.1", "172.2", "172.3", "192.168."} {
		if len(got) >= len(bad) && got[:len(bad)] == bad {
			t.Errorf("default link %q sits inside the private range %q", got, bad)
		}
	}
	if custom := (MasterSpec{NetnsCIDR: "100.64.7.0/30"}).NetnsLinkCIDR(); custom != "100.64.7.0/30" {
		t.Errorf("an explicit link was ignored: %q", custom)
	}
}
