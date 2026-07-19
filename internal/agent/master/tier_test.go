package master

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fixedProbe returns a memberProbe answering from a per-exit table of
// (reachable, probed) results. A missing entry means the probe errored (blind).
func fixedProbe(t map[string][2]int) memberProbe {
	return func(_ context.Context, name string) (int, int, error) {
		r, ok := t[name]
		if !ok {
			return 0, 0, errors.New("clash API unreachable")
		}
		return r[0], r[1], nil
	}
}

// testSelector pairs a selector with its probe so tests read like the call site.
type testSelector struct {
	*tierSelector
	probe memberProbe
}

func (s testSelector) active(primary, reserve []string) bool {
	return s.ReserveActive(context.Background(), s.probe, primary, reserve)
}

func newTestSelector(p memberProbe) testSelector {
	s := newTierSelector(nil)
	s.now = func() time.Time { return time.Unix(0, 0) }
	return testSelector{tierSelector: s, probe: p}
}

var (
	primary = []string{"vn1", "vn2"}
	reserve = []string{"1cnode004"}
)

func TestTierStaysOnPrimaryWhileHealthy(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}}))
	for i := range 5 {
		if s.active(primary, reserve) {
			t.Fatalf("pass %d: must stay on the primary tier", i)
		}
	}
}

func TestTierFailsOverOnlyAfterStreak(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}))
	if s.active(primary, reserve) {
		t.Fatal("a single failed pass must not flip the data plane")
	}
	if !s.active(primary, reserve) {
		t.Fatalf("must fail over after %d consecutive failures", defaultTierFailStreak)
	}
}

// The pn8 case: an exit that answers exactly one destination is censored, not
// healthy. A single-URL check would keep it in rotation.
func TestTierTreatsSingleReachableDestinationAsUnusable(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {1, 4}, "vn2": {1, 4}}))
	s.active(primary, reserve)
	if !s.active(primary, reserve) {
		t.Fatal("reaching only 1 of 4 destinations must count as unusable")
	}
}

// A tier is down only when EVERY member is: mihomo balances across whatever lives.
func TestTierUsableWhileAnyMemberIsHealthy(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {0, 4}, "vn2": {4, 4}}))
	for i := range 4 {
		if s.active(primary, reserve) {
			t.Fatalf("pass %d: one healthy member keeps the tier up", i)
		}
	}
}

// An unreachable Clash API must never move the data plane — a control-plane
// hiccup turning into a failover is strictly worse than doing nothing.
func TestTierHoldsDecisionWhenProbeIsBlind(t *testing.T) {
	s := newTestSelector(fixedProbe(nil)) // every probe errors
	for i := range 5 {
		if s.active(primary, reserve) {
			t.Fatalf("pass %d: a blind probe must hold the current tier", i)
		}
	}
	if s.consecFail != 0 {
		t.Errorf("blind passes must not accumulate a failure streak, got %d", s.consecFail)
	}
}

func TestTierRecoveryNeedsLongerStreakThanFailure(t *testing.T) {
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}
	s := newTestSelector(fixedProbe(table))
	s.minHold = 0 // isolate the streak rule from the hold rule

	for range defaultTierFailStreak {
		s.active(primary, reserve)
	}
	if !s.reserveActive {
		t.Fatal("expected to be on the reserve tier")
	}

	// Primary comes back.
	table["vn1"] = [2]int{4, 4}
	table["vn2"] = [2]int{4, 4}
	for i := range defaultTierRecoverStreak - 1 {
		if !s.active(primary, reserve) {
			t.Fatalf("pass %d: must not fail back before the recovery streak is met", i)
		}
	}
	if s.active(primary, reserve) {
		t.Fatal("must fail back once the recovery streak is met")
	}
}

// Each flip rewrites config.yaml and reloads mihomo, which resets group health —
// so flips must be rate-limited even when the streaks say otherwise.
func TestTierMinHoldSuppressesRapidFlapping(t *testing.T) {
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}
	s := newTestSelector(fixedProbe(table))
	now := time.Unix(0, 0)
	s.now = func() time.Time { return now }

	for range defaultTierFailStreak {
		s.active(primary, reserve)
	}
	if !s.reserveActive {
		t.Fatal("expected the initial failover")
	}

	// Primary recovers immediately and stays healthy well past the recovery streak,
	// but the hold window has not elapsed.
	table["vn1"] = [2]int{4, 4}
	table["vn2"] = [2]int{4, 4}
	now = now.Add(time.Minute)
	for range defaultTierRecoverStreak * 3 {
		if !s.active(primary, reserve) {
			t.Fatal("must not fail back inside the min-hold window")
		}
	}

	// Past the window, the next satisfied streak flips.
	now = now.Add(defaultTierMinHold)
	var back bool
	for range defaultTierRecoverStreak {
		back = !s.active(primary, reserve)
	}
	if !back {
		t.Fatal("must fail back once min-hold has elapsed")
	}
}

func TestTierNoReserveNeverFailsOver(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}))
	for range 5 {
		if s.active(primary, nil) {
			t.Fatal("with no reserve tier there is nowhere to fail over to")
		}
	}
}

// minReachable must not exceed what was actually probed, or a short URL list
// would make every exit look unusable.
func TestTierMinReachableClampsToProbedCount(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {1, 1}, "vn2": {1, 1}}))
	for i := range 3 {
		if s.active(primary, reserve) {
			t.Fatalf("pass %d: 1/1 reachable must count as usable", i)
		}
	}
}
