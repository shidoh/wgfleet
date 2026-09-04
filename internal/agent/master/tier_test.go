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
	*TierSelector
	probe memberProbe
}

func (s testSelector) active(primary, reserve []string) bool {
	return s.ReserveActive(context.Background(), s.probe, primary, reserve)
}

func newTestSelector(p memberProbe) testSelector {
	s := NewTierSelector(nil)
	s.now = func() time.Time { return time.Unix(0, 0) }
	return testSelector{TierSelector: s, probe: p}
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

// countingProbe wraps a table and records how many times each member was probed,
// so warm-up behaviour can be asserted without timing.
func countingProbe(t map[string][2]int, hits map[string]int) memberProbe {
	return func(_ context.Context, name string) (int, int, error) {
		hits[name]++
		r, ok := t[name]
		if !ok {
			return 0, 0, errors.New("clash API unreachable")
		}
		return r[0], r[1], nil
	}
}

// The flat group (ADR-0029 rev 2) leaves reserve proxies in no group, so nothing
// dials them and their WireGuard tunnels go cold — observed live as a reserve exit
// going Degraded on "stale handshake (1h23m45s old)" while every other check passed.
func TestTierWarmsIdleReserve(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(countingProbe(table, hits))
	for range 6 {
		s.active(primary, reserve)
	}
	if hits["1cnode004"] == 0 {
		t.Fatal("an idle reserve exit must still be probed, or its tunnel goes cold")
	}
	// Warmed on a cadence, not every pass — it must not cost a full probe sweep per
	// reconcile.
	if hits["1cnode004"] >= 6 {
		t.Fatalf("reserve probed %d times in 6 passes, want a cadence", hits["1cnode004"])
	}
}

// Warming must be observational only: the standby's condition answers a different
// question than "should we leave the active tier".
func TestTierWarmingDoesNotAffectTheDecision(t *testing.T) {
	hits := map[string]int{}
	// Primary healthy, reserve entirely dead.
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {0, 4}}
	s := newTestSelector(countingProbe(table, hits))
	for i := range 6 {
		if s.active(primary, reserve) {
			t.Fatalf("pass %d: a dead standby must not push us off a healthy primary", i)
		}
	}
	usable, total := s.StandbyHealth()
	if total == 0 {
		t.Fatal("standby health must be sampled")
	}
	if usable != 0 {
		t.Fatalf("standby usable = %d, want 0 — every reserve member was unreachable", usable)
	}
}

// Knowing the standby is healthy is the other half of a sane failover decision.
func TestTierRecordsStandbyHealth(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {3, 4}}
	s := newTestSelector(countingProbe(table, hits))
	for range 4 {
		s.active(primary, reserve)
	}
	usable, total := s.StandbyHealth()
	if usable != 1 || total != 1 {
		t.Fatalf("standby health = %d/%d, want 1/1", usable, total)
	}
}

// Once the reserve is carrying traffic it is warm by definition, and the primary is
// already probed every pass as the recovery check — warming again would double the
// probe load for nothing.
func TestTierDoesNotWarmWhileReserveIsActive(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(countingProbe(table, hits))
	s.minHold = 0
	for range defaultTierFailStreak {
		s.active(primary, reserve)
	}
	if !s.reserveActive {
		t.Fatal("expected failover to the reserve tier")
	}
	before := hits["1cnode004"]
	for range 6 {
		s.active(primary, reserve)
	}
	if hits["1cnode004"] != before {
		t.Fatalf("reserve probed %d more times while ACTIVE; it is warm by definition",
			hits["1cnode004"]-before)
	}
}

// Planners() runs on EVERY reconcile pass (the agent rebuilds the engine each
// time), so the selector must come from the caller and be reused. When it was
// constructed inside Planners the hysteresis reset every 30s: streaks never
// reached their thresholds, so failover could not fire and the standby was never
// warmed — and every individual pass still looked correct, which is why it went
// unnoticed until a reserve exit went Degraded on a stale handshake.
func TestPlannersReusesTheCallersTierSelector(t *testing.T) {
	tier := NewTierSelector(nil)
	var found *TierSelector
	for _, p := range Planners(Input{Paths: PathsUnder(t.TempDir()), Tier: tier}) {
		if mp, ok := p.(mihomoPlanner); ok {
			found = mp.tier
		}
	}
	if found == nil {
		t.Fatal("no mihomoPlanner in the master planner set")
	}
	if found != tier {
		t.Fatal("mihomoPlanner must carry the caller's selector, not a fresh one — " +
			"a per-pass selector silently disables failover")
	}
}

// Two consecutive passes on ONE selector must accumulate, which is the property a
// per-pass selector destroys.
func TestTierStreaksSurviveAcrossPasses(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}))
	s.active(primary, reserve)
	if s.consecFail != 1 {
		t.Fatalf("after one failed pass consecFail = %d, want 1", s.consecFail)
	}
	s.active(primary, reserve)
	if !s.reserveActive {
		t.Fatal("streaks must accumulate across passes and trigger failover")
	}
}

// The early exit keeps a healthy tier cheap, but a fixed start index made
// members[0] absorb every probe forever: measured live, vn1 took ~5 samples per
// cycle to vn2's 1, and only vn1 showed latency spread. Probing must rotate.
func TestTierProbeLoadRotatesAcrossMembers(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(countingProbe(table, hits))
	for range 10 {
		s.active(primary, reserve)
	}
	if hits["vn1"] == 0 || hits["vn2"] == 0 {
		t.Fatalf("both primary members must be sampled, got vn1=%d vn2=%d", hits["vn1"], hits["vn2"])
	}
	// Neither may carry more than ~2x the other's share.
	hi, lo := max(hits["vn1"], hits["vn2"]), min(hits["vn1"], hits["vn2"])
	if hi > lo*2 {
		t.Fatalf("probe load is lopsided: vn1=%d vn2=%d", hits["vn1"], hits["vn2"])
	}
}

// Rotation must not cost the early exit — a healthy tier still stops at one member.
func TestTierHealthyTierStillProbesOnlyOneMember(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(countingProbe(table, hits))
	s.warmEvery = 0 // isolate the decision probe from the warm probe
	s.active(primary, reserve)
	if got := hits["vn1"] + hits["vn2"]; got != 1 {
		t.Fatalf("healthy tier probed %d members, want 1 (early exit)", got)
	}
}

// A fully drained primary tier (ADR-0010) is starvation, not ill health: there is
// nothing left to probe. wgBestGroups already falls back to the non-empty tier, so
// the selector must report the reserve — otherwise its own view of where traffic
// goes contradicts the config it just rendered, and warmStandby then keeps the
// CARRYING tier warm while letting the idle one go cold.
func TestTierEmptyPrimaryReportsReserve(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"1cnode004": {4, 4}}))
	if !s.active(nil, reserve) {
		t.Fatal("a fully drained primary must route to the reserve tier")
	}
	if !s.reserveActive {
		t.Fatal("internal state must agree with the reported tier")
	}
}

// With no reserve there is nowhere to go, drained primary or not.
func TestTierEmptyPrimaryAndNoReserveStaysPrimary(t *testing.T) {
	s := newTestSelector(fixedProbe(nil))
	if s.active(nil, nil) {
		t.Fatal("with no reserve there is nothing to fail over to")
	}
}

// Coming back from starvation must go through the normal recovery hysteresis, not
// snap straight back the moment one primary member returns.
func TestTierRecoveryFromStarvationUsesHysteresis(t *testing.T) {
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(fixedProbe(table))
	s.minHold = 0

	if !s.active(nil, reserve) {
		t.Fatal("expected the starved primary to report reserve")
	}
	// Primary members return. The first passes must NOT flip back immediately.
	for i := range defaultTierRecoverStreak - 1 {
		if !s.active(primary, reserve) {
			t.Fatalf("pass %d: must not fail back before the recovery streak is met", i)
		}
	}
	if s.active(primary, reserve) {
		t.Fatal("must fail back once the recovery streak is met")
	}
}

// The whole point of the multi-destination probe is that it is stricter than the
// check mihomo's own group runs (one lightweight URL, every `interval`). Both
// write the SAME state: `GET /proxies/{name}/delay` is not a read — it records the
// result and flips the proxy's `alive` flag, which is what removes a member from a
// load-balance group. Verified on the live master 2026-09-04.
//
// So the two criteria fight over one flag. Ours evicts a censored or dead exit;
// mihomo's weaker check puts it straight back within the interval. Measured on the
// live fleet: 27 "failed multi-destination probe" verdicts in 13 days (vn2 x13,
// vn0 x9, vn1 x5) — and every one of them was undone rather than sustained,
// because the early exit below meant we often did not probe that member again for
// several passes. A broken exit therefore MIGRATED in and out of rotation instead
// of staying out of it.
//
// Re-probing every held-out member on every pass is what makes our verdict stick:
// a failing probe re-writes the flag, so mihomo's revival survives at most one
// interval instead of half the time.
func TestHeldOutExitIsReprobedEveryPass(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {0, 4}}
	s := newTestSelector(countingProbe(table, hits))
	s.warmEvery = 0 // isolate the decision probe from the warm probe

	const passes = 6
	for range passes {
		s.active(primary, reserve)
	}

	// vn2 cannot be probed on the very first pass if rotation started at vn1 and
	// vn1 answered, so allow one pass of slack — but no more.
	if hits["vn2"] < passes-1 {
		t.Fatalf("a held-out exit was probed %d times in %d passes; it must be re-probed "+
			"EVERY pass, or mihomo's own weaker check revives it and the exit flaps",
			hits["vn2"], passes)
	}
}

// The hold is a watch window, not a quarantine: once the exit answers again our
// probe writes `alive` back itself, so recovery must not need an operator. What
// the window buys is that we keep sampling it every pass for a little longer,
// rather than dropping it back into the rotating scan on its first good answer.
func TestHeldOutExitReturnsToRotationAfterCleanPasses(t *testing.T) {
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}
	s := newTestSelector(fixedProbe(table))
	s.minHold = 0

	s.active(primary, reserve)
	if len(s.heldOut) != len(primary) {
		t.Fatalf("every failing member must be held out, held = %v", s.heldOut)
	}

	table["vn1"] = [2]int{4, 4}
	table["vn2"] = [2]int{4, 4}
	for range defaultHoldRecover {
		s.active(primary, reserve)
	}
	if len(s.heldOut) != 0 {
		t.Fatalf("a recovered exit must return to the normal rotation, still held: %v", s.heldOut)
	}
}

// An unreachable Clash API is not evidence about the exit. It must neither hold a
// member out nor release one that is already held — the same rule the tier
// decision already follows, applied to the per-member verdict.
func TestBlindProbeNeitherHoldsNorReleases(t *testing.T) {
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}}
	s := newTestSelector(fixedProbe(table))
	s.active(primary, reserve)
	if len(s.heldOut) != len(primary) {
		t.Fatalf("setup: expected both members held, got %v", s.heldOut)
	}

	blind := newTestSelector(fixedProbe(nil))
	blind.active(primary, reserve)
	if len(blind.heldOut) != 0 {
		t.Fatalf("a blind probe must not hold anything out, got %v", blind.heldOut)
	}

	// Now make every probe blind for the selector that IS holding members.
	s.probe = fixedProbe(nil)
	for range defaultHoldRecover + 2 {
		s.active(primary, reserve)
	}
	if len(s.heldOut) != len(primary) {
		t.Fatalf("blind passes must not release a held-out exit, held = %v", s.heldOut)
	}
}

// The held-out verdict lives only in this selector's memory. mihomo's own view
// (exported by the controller as wgfleet_exit_tunnel_alive) shows the EFFECT — an
// exit out of the load balancer — but never the cause, and the cause is what an
// operator needs at 4am. Rotation() is what the agent turns into a metric.
func TestRotationReportsTheActiveTierAndItsHeldOutMembers(t *testing.T) {
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {0, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(fixedProbe(table))

	// Two passes: the first may stop at vn1 by rotation, the second reaches vn2.
	s.active(primary, reserve)
	s.active(primary, reserve)

	rot := s.Rotation()
	if len(rot) != len(primary) {
		t.Fatalf("rotation must cover exactly the tier carrying traffic, got %v", rot)
	}
	if rot["vn2"] != true {
		t.Errorf("vn2 fails 0/4 destinations and must read as held out, got %v", rot)
	}
	if rot["vn1"] != false {
		t.Errorf("vn1 is healthy and must read as in rotation, got %v", rot)
	}
	// A reserve member is not in the group at all, so "held out" is meaningless for
	// it — reporting one would invite an alert on an exit that carries no traffic
	// by design.
	if _, ok := rot["1cnode004"]; ok {
		t.Errorf("the idle reserve tier must not appear in rotation, got %v", rot)
	}
}

// Once traffic moves to the reserve, THAT is the tier in rotation. Reporting the
// primary would describe a group mihomo is no longer routing through.
func TestRotationFollowsTheTierThatCarriesTraffic(t *testing.T) {
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {0, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(fixedProbe(table))
	s.minHold = 0
	for range defaultTierFailStreak {
		s.active(primary, reserve)
	}
	if !s.ReserveIsActive() {
		t.Fatal("expected failover to the reserve tier")
	}
	rot := s.Rotation()
	if _, ok := rot["1cnode004"]; !ok {
		t.Fatalf("the reserve tier now carries traffic and must be the reported rotation, got %v", rot)
	}
	if _, ok := rot["vn1"]; ok {
		t.Fatalf("the idle primary must not be reported as in rotation, got %v", rot)
	}
}

// ReserveIsActive must READ the decision, never take one: a metrics call has no
// business burning Clash API probes or advancing the hysteresis.
func TestReserveIsActiveDoesNotProbe(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(countingProbe(table, hits))
	s.active(primary, reserve)
	before, pass := hits["vn1"]+hits["vn2"]+hits["1cnode004"], s.pass

	for range 5 {
		s.ReserveIsActive()
		s.Rotation()
	}
	if after := hits["vn1"] + hits["vn2"] + hits["1cnode004"]; after != before {
		t.Errorf("reading the tier state probed %d extra times", after-before)
	}
	if s.pass != pass {
		t.Errorf("reading the tier state advanced the pass counter to %d, want %d", s.pass, pass)
	}
}
