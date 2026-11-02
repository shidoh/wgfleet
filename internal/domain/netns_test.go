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
	wanted, err := MasterSpec{}.NetnsWanted()
	if err != nil {
		t.Fatalf("an unset knob is not an error: %v", err)
	}
	if !wanted {
		t.Error("an unset client_via_netns left the master on the host path; the fix ships off by default")
	}
}

// And "off" is the whole way out: an operator who wants the old path says so.
func TestNetnsWantedOffIsTheWayBack(t *testing.T) {
	wanted, err := MasterSpec{ClientViaNetns: "off"}.NetnsWanted()
	if err != nil || wanted {
		t.Fatalf("off did not decline the move (wanted=%v, err=%v)", wanted, err)
	}
}

func TestNetnsWantedModes(t *testing.T) {
	for _, tc := range []struct {
		value    string
		wantMove bool
	}{
		{"off", false},
		{"auto", true},
		{" auto ", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			move, err := MasterSpec{ClientViaNetns: tc.value}.NetnsWanted()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if move != tc.wantMove {
				t.Errorf("move = %v, want %v", move, tc.wantMove)
			}
		})
	}
}

// A per-client selection is refused, and the refusal explains itself rather than
// just saying no.
//
// It existed, was implemented, and was measured on a test stand doing the
// opposite of what its name promised: mihomo moves as a whole, so the host went on
// steering every client OUTSIDE the prefix at listeners that had left — the blast
// radius of a "canary" was everyone except the canary. `tproxy` can only reach a
// socket in its own namespace and there is one mihomo, so this is not deferred
// work but a fact about the kernel.
func TestNetnsWantedRefusesAPerClientSelection(t *testing.T) {
	move, err := MasterSpec{ClientViaNetns: "10.80.0.7/32"}.NetnsWanted()
	if err == nil {
		t.Fatal("a per-client selection was accepted")
	}
	if move {
		t.Fatal("a refused value still enabled the move")
	}
	if !strings.Contains(err.Error(), "cannot be taken per client") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// A value that is neither mode used to be read as a per-client prefix, so "of" —
// one keystroke short of "off" — silently turned the migration ON. A typo in a
// manifest must never enable a data-plane change.
func TestNetnsWantedRefusesATypoInsteadOfEnablingTheMove(t *testing.T) {
	for _, v := range []string{"of", "on", "yes", "true", "2001:db8::/64"} {
		t.Run(v, func(t *testing.T) {
			move, err := MasterSpec{ClientViaNetns: v}.NetnsWanted()
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
