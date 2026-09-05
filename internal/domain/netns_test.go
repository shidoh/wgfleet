package domain

import (
	"strings"
	"testing"
)

// An unset knob must not move anything. The default is a rollout decision, not a
// design one: the automatic revert it would rely on has not been exercised end to
// end, and until it has, a fleet that swaps the binary must keep the path it had.
func TestNetnsWantedDefaultsToTheHostPath(t *testing.T) {
	wanted, canary, err := MasterSpec{}.NetnsWanted()
	if err != nil {
		t.Fatalf("an unset knob is not an error: %v", err)
	}
	if wanted {
		t.Error("an unset client_via_netns moved client interception on its own")
	}
	if canary != "" {
		t.Errorf("an unset knob produced a canary %q", canary)
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
