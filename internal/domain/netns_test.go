package domain

import (
	"strings"
	"testing"
)

// An unset knob moves. The failure this migration removes is not something an
// operator can be expected to know they have — every UDP port the host holds is a
// silent black hole for client traffic to that port — so shipping it off by
// default ships the outage by default.
//
// What makes that defensible is the sequence the agent performs on its own:
// prove the namespace works, measure the client path after, revert if it breaks.
func TestNetnsWantedDefaultsToMoving(t *testing.T) {
	wanted, canary, err := MasterSpec{}.NetnsWanted()
	if err != nil {
		t.Fatalf("an unset knob is not an error: %v", err)
	}
	if !wanted {
		t.Error("an unset client_via_netns left the master on the host path; the fix ships off by default")
	}
	if canary != "" {
		t.Errorf("an unset knob produced a canary %q; it must move every client", canary)
	}
}

// And "off" is still the whole way out: an operator who wants the old path says so.
func TestNetnsWantedOffIsTheWayBack(t *testing.T) {
	wanted, _, err := MasterSpec{ClientViaNetns: "off"}.NetnsWanted()
	if err != nil || wanted {
		t.Fatalf("off did not decline the move (wanted=%v, err=%v)", wanted, err)
	}
}

func TestNetnsWantedModes(t *testing.T) {
	for _, tc := range []struct {
		value      string
		wantMove   bool
		wantCanary string
	}{
		{"off", false, ""},
		{"auto", true, ""},
		{" auto ", true, ""},
		{"10.80.0.7/32", true, "10.80.0.7/32"},
		// A host address inside a wider prefix is canonicalised: the value ends up in
		// an `ip rule` argument and in a rendered nft guard, and two spellings of one
		// prefix must not be able to describe two different rules.
		{"10.80.0.7/24", true, "10.80.0.0/24"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			move, canary, err := MasterSpec{ClientViaNetns: tc.value}.NetnsWanted()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if move != tc.wantMove {
				t.Errorf("move = %v, want %v", move, tc.wantMove)
			}
			if canary != tc.wantCanary {
				t.Errorf("canary = %q, want %q", canary, tc.wantCanary)
			}
		})
	}
}

// A value that is neither a mode nor a CIDR used to be read as a canary prefix, so
// "of" — one keystroke short of "off" — silently turned the migration ON for a
// prefix matching nothing. A typo in a manifest must never enable a data-plane
// change.
func TestNetnsWantedRefusesATypoInsteadOfEnablingTheMove(t *testing.T) {
	for _, v := range []string{"of", "on", "yes", "true", "10.80.0.0/33", "2001:db8::/64"} {
		t.Run(v, func(t *testing.T) {
			move, _, err := MasterSpec{ClientViaNetns: v}.NetnsWanted()
			if err == nil {
				t.Fatalf("%q was accepted", v)
			}
			if move {
				t.Fatalf("%q was rejected AND enabled the move", v)
			}
			if !strings.Contains(err.Error(), "client_via_netns") {
				t.Errorf("the error does not name the knob: %v", err)
			}
		})
	}
}
