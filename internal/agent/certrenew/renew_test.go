package certrenew

import (
	"fmt"
	"testing"
	"time"
)

func TestDueAtLandsInsideTheWindowAndSpreadsTheFleet(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	life := notAfter.Sub(notBefore)

	seen := map[time.Time]bool{}
	for i := 0; i < 200; i++ {
		node := fmt.Sprintf("exit-%02d", i)
		at := DueAt(node, notBefore, notAfter)
		frac := float64(at.Sub(notBefore)) / float64(life)
		if frac < windowLow || frac >= windowHigh {
			t.Fatalf("%s renews at %.3f of its life, outside [%.2f,%.2f)", node, frac, windowLow, windowHigh)
		}
		if left := notAfter.Sub(at); left < 30*24*time.Hour {
			t.Fatalf("%s starts renewing with only %v left", node, left)
		}
		seen[at] = true
	}
	// Certificates issued together must not renew together, or a routine rotation
	// becomes the same fleet-wide event that made expiry dangerous.
	if len(seen) < 150 {
		t.Errorf("%d distinct renewal moments across 200 nodes; the fleet renews in a clump", len(seen))
	}
}

func TestDueAtIsStableAcrossRestarts(t *testing.T) {
	nb := time.Now()
	na := nb.Add(365 * 24 * time.Hour)
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("node-%d", i)
		if a, b := DueAt(id, nb, na), DueAt(id, nb, na); !a.Equal(b) {
			t.Fatalf("%s: %v then %v — a restart must not move the date", id, a, b)
		}
	}
}

func TestDueIsFalseEarlyAndTrueLate(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(365 * 24 * time.Hour)
	if Due("exit-de-1", nb, na, nb.Add(24*time.Hour)) {
		t.Error("renewing on day one throws away the certificate's whole life")
	}
	if !Due("exit-de-1", nb, na, na.Add(-time.Hour)) {
		t.Error("an hour before expiry is certainly due")
	}
	if !Due("x", na, nb, na) {
		t.Error("an inverted validity period should read as due, not as never")
	}
}
