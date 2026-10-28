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

// A standby transport is in no tier, so nothing here dials it: not the tier
// decision (it probes the active tier), not warmStandby (it probes the inactive
// TIER). Measured live 2026-09-04 — five of six exits had a standby transport and
// none had ever been health-checked; four reported alive=1, which is mihomo's
// default for an untested proxy rather than a measurement.
//
// The cost of not knowing is paid at the worst moment: switching transport is an
// emergency move made precisely when the active path is blocked, and it is not
// the time to discover the other one is dead too.
func TestStandbyTransportsAreProbedOnTheirOwnCadence(t *testing.T) {
	hits := map[string]int{}
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {4, 4}, "vn1-reality": {4, 4}}
	s := newTestSelector(countingProbe(table, hits))
	s.warmEvery = 0 // isolate this from the reserve-tier warm probe

	standby := []string{"vn1-reality"}
	for range defaultStandbyEvery * 2 {
		s.active(primary, reserve)
		s.ProbeStandbyTransports(context.Background(), s.probe, standby)
	}
	if hits["vn1-reality"] == 0 {
		t.Fatal("a standby transport must be probed, or its health is never known until the switch")
	}
	// Rarely, though: it carries no traffic, and a heartbeat on a path we keep in
	// reserve is a cost with no matching benefit.
	if hits["vn1-reality"] > 3 {
		t.Errorf("standby probed %d times in %d passes, want a slow cadence",
			hits["vn1-reality"], defaultStandbyEvery*2)
	}
	if usable, ok := s.StandbyTransportHealth()["vn1-reality"]; !ok || !usable {
		t.Errorf("a reachable standby must record usable, got %v", s.StandbyTransportHealth())
	}
}

func TestStandbyTransportRecordsUnusable(t *testing.T) {
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "vn1-reality": {0, 4}}
	s := newTestSelector(fixedProbe(table))
	for range defaultStandbyEvery {
		s.active(primary, reserve)
		s.ProbeStandbyTransports(context.Background(), s.probe, []string{"vn1-reality"})
	}
	usable, ok := s.StandbyTransportHealth()["vn1-reality"]
	if !ok {
		t.Fatal("the standby must be recorded even when it fails — silence reads as healthy")
	}
	if usable {
		t.Error("a standby reaching 0 of 4 destinations must record unusable")
	}
}

// An unreachable Clash API says nothing about the standby. Recording a failure
// there would turn a control-plane hiccup into "your fallback is gone".
func TestStandbyTransportBlindProbeKeepsTheLastVerdict(t *testing.T) {
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "vn1-reality": {4, 4}}
	s := newTestSelector(fixedProbe(table))
	for range defaultStandbyEvery {
		s.active(primary, reserve)
		s.ProbeStandbyTransports(context.Background(), s.probe, []string{"vn1-reality"})
	}
	if !s.StandbyTransportHealth()["vn1-reality"] {
		t.Fatal("setup: expected a usable standby")
	}

	blind := fixedProbe(map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}}) // vn1-reality errors
	for range defaultStandbyEvery * 2 {
		s.active(primary, reserve)
		s.ProbeStandbyTransports(context.Background(), blind, []string{"vn1-reality"})
	}
	if !s.StandbyTransportHealth()["vn1-reality"] {
		t.Error("a blind sample must not overwrite the last real verdict")
	}
}

// An exit that stops having a standby — its second transport disabled, or the
// whole node drained — must stop reporting one, not freeze on its last value.
func TestStandbyTransportForgetsExitsThatNoLongerHaveOne(t *testing.T) {
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {4, 4}, "vn1-reality": {0, 4}}
	s := newTestSelector(fixedProbe(table))
	for range defaultStandbyEvery {
		s.active(primary, reserve)
		s.ProbeStandbyTransports(context.Background(), s.probe, []string{"vn1-reality"})
	}
	if len(s.StandbyTransportHealth()) != 1 {
		t.Fatalf("setup: expected one standby, got %v", s.StandbyTransportHealth())
	}
	for range defaultStandbyEvery {
		s.active(primary, reserve)
		s.ProbeStandbyTransports(context.Background(), s.probe, nil)
	}
	if got := s.StandbyTransportHealth(); len(got) != 0 {
		t.Errorf("a vanished standby must stop being reported, got %v", got)
	}
}

// Rotation() answers "is this exit held out"; an operator looking at the console
// needs the two facts that follow from it — how many destinations answered, and
// how long the spell has been running. Both are already known at the moment the
// verdict is taken; until now they were dropped on the floor and survived only in
// the journal, which is why a held-out exit read as an unexplained "not carrying".
func TestRotationVerdictsCarryTheProbeResultAndWhenTheHoldBegan(t *testing.T) {
	table := map[string][2]int{"vn1": {4, 4}, "vn2": {0, 4}, "1cnode004": {4, 4}}
	s := newTestSelector(fixedProbe(table))
	clock := time.Unix(1000, 0)
	s.now = func() time.Time { return clock }

	// Two passes: the first may stop at vn1 by rotation, the second reaches vn2.
	s.active(primary, reserve)
	s.active(primary, reserve)

	v := s.RotationVerdicts()
	if len(v) != len(primary) {
		t.Fatalf("verdicts must cover exactly the tier carrying traffic, got %v", v)
	}
	vn2 := v["vn2"]
	if !vn2.HeldOut {
		t.Errorf("vn2 fails 0/4 destinations and must read as held out, got %+v", vn2)
	}
	if vn2.Reachable != 0 || vn2.Probed != 4 {
		t.Errorf("the verdict must carry the probe result that produced it, got %+v", vn2)
	}
	if !vn2.Since.Equal(clock) {
		t.Errorf("the hold must be stamped with the time it began, got %+v", vn2)
	}
	if vn1 := v["vn1"]; vn1.HeldOut {
		t.Errorf("vn1 is healthy and must not read as held out, got %+v", vn1)
	}
}

// The stamp is when the spell BEGAN, not when it was last re-confirmed. A clock
// that restarted on every failing pass would report "held out for 30 seconds"
// forever, which is precisely the reading that makes an operator wait it out.
func TestRotationVerdictKeepsTheStartOfTheSpellAcrossPasses(t *testing.T) {
	// vn2 stays healthy so the tier remains usable and no failover moves the
	// rotation out from under the assertion.
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {0, 4}, "vn2": {4, 4}}))
	clock := time.Unix(1000, 0)
	s.now = func() time.Time { return clock }

	// The scan starts at a rotating offset, so give it enough passes to reach vn1.
	for range 3 {
		s.active(primary, reserve)
	}
	began := s.RotationVerdicts()["vn1"].Since
	if began.IsZero() {
		t.Fatal("a held-out member must be stamped on the pass that held it out")
	}

	clock = clock.Add(9 * time.Minute)
	s.active(primary, reserve)
	s.active(primary, reserve)
	if got := s.RotationVerdicts()["vn1"].Since; !got.Equal(began) {
		t.Errorf("a still-failing member keeps the start of its spell: began %v, got %v", began, got)
	}
}

// A member that comes back must stop reporting a hold: the console reads these
// fields directly, and a stale "held out since" on a carrying exit is a lie in
// the one place an operator goes to check.
func TestRotationVerdictClearsWhenTheMemberRecovers(t *testing.T) {
	table := map[string][2]int{"vn1": {0, 4}, "vn2": {4, 4}}
	s := newTestSelector(fixedProbe(table))
	for range 3 {
		s.active(primary, reserve)
	}
	if !s.RotationVerdicts()["vn1"].HeldOut {
		t.Fatal("expected vn1 held out after a failing pass")
	}

	table["vn1"] = [2]int{4, 4}
	for range defaultHoldRecover {
		s.active(primary, reserve)
	}
	v := s.RotationVerdicts()["vn1"]
	if v.HeldOut || !v.Since.IsZero() {
		t.Errorf("a recovered member must carry no hold, got %+v", v)
	}
}

// The warm probe of the idle reserve tier knew which member failed and threw the
// name away, reporting only "1 of 3 usable". An aggregate cannot be acted on: the
// alert only fires when EVERY reserve member is dead, and until then the console
// shows a reserve exit that looks exactly like a healthy one. Live 2026-09-11:
// 1cnode004's active path was failing for minutes at a time behind a 3/3.
func TestWarmProbeKeepsAPerMemberVerdictNotJustTheTally(t *testing.T) {
	table := map[string][2]int{
		"vn1": {4, 4}, "vn2": {4, 4},
		"1cnode004": {0, 4}, "anz3": {4, 4},
	}
	s := newTestSelector(fixedProbe(table))
	res := []string{"1cnode004", "anz3"}

	// The warm probe runs on a cadence; give it enough passes to land on one.
	for range defaultWarmEvery + 1 {
		s.active(primary, res)
	}

	v := s.StandbyVerdicts()
	bad, ok := v["1cnode004"]
	if !ok {
		t.Fatalf("the failing reserve member must be named, got %v", v)
	}
	if bad.HeldOut {
		t.Errorf("a reserve member is in no rotation and must not read as held out: %+v", bad)
	}
	if bad.Reachable != 0 || bad.Probed != 4 {
		t.Errorf("the verdict must carry the probe result, got %+v", bad)
	}
	if good := v["anz3"]; good.Reachable != 4 || good.Probed != 4 {
		t.Errorf("a healthy reserve member must carry its clean sample, got %+v", good)
	}
}

// A member that leaves the reserve set must stop being reported, or the console
// keeps a verdict about an exit that is no longer there.
func TestStandbyVerdictsForgetMembersThatLeaveTheTier(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{
		"vn1": {4, 4}, "vn2": {4, 4}, "1cnode004": {0, 4}, "anz3": {4, 4},
	}))
	for range defaultWarmEvery + 1 {
		s.active(primary, []string{"1cnode004", "anz3"})
	}
	for range defaultWarmEvery + 1 {
		s.active(primary, []string{"anz3"})
	}
	if _, ok := s.StandbyVerdicts()["1cnode004"]; ok {
		t.Error("an exit dropped from the reserve tier must stop being reported")
	}
}

// budgetProbe answers from table like fixedProbe, but only for the first n calls:
// after that every call is blind, the way budgetedProbe turns a member it has no
// time left for into an error. Build a fresh one per pass — the budget is per pass.
func budgetProbe(table map[string][2]int, n int) memberProbe {
	calls := 0
	return func(ctx context.Context, name string) (int, int, error) {
		calls++
		if calls > n {
			return 0, 0, errors.New("probing phase out of budget")
		}
		return fixedProbe(table)(ctx, name)
	}
}

func (s *testSelector) budgetedPass(table map[string][2]int, n int, primary, reserve []string) bool {
	s.probe = budgetProbe(table, n)
	return s.active(primary, reserve)
}

// Live 2026-09-28: vn0 and vn0-reality were dead and held out, and each burned a
// full probe timeout every pass. The phase budget ran out on them, the healthy
// member was never asked, and the pass counted as "primary unusable" — so the
// recovery streak reset every minute or two and the fleet sat on the reserve.
func TestDeadHeldMembersDoNotStarveAHealthyOne(t *testing.T) {
	members := []string{"vn0", "vn0-reality", "vn1", "vn2"}
	table := map[string][2]int{"vn0": {0, 4}, "vn0-reality": {0, 4}, "vn1": {4, 4}, "vn2": {0, 4}}
	s := newTestSelector(nil)
	s.warmEvery = 0
	s.minHold = 0
	s.reserveActive = true
	s.heldOut = map[string]holdRecord{"vn0": {}, "vn0-reality": {}, "vn2": {}}

	for i := range s.recoverStreak {
		// Two attempts per pass: exactly what two dead members' timeouts leave room for.
		if !s.budgetedPass(table, 2, members, reserve) {
			return // recovered
		}
		if s.consecOK != i+1 {
			t.Fatalf("pass %d: the healthy member must be sampled every pass, consec_ok = %d", i, s.consecOK)
		}
	}
	t.Fatalf("still on the reserve after %d passes with a healthy primary member", s.recoverStreak)
}

// Live 2026-09-28 10:34: the failover was decided while vn2 had not been probed at
// all. A member the budget never reached is unknown, not down.
func TestUnprobedMemberIsNotCountedAsDown(t *testing.T) {
	members := []string{"vn0", "vn0-reality", "vn1", "vn2"}
	table := map[string][2]int{"vn0": {0, 4}, "vn0-reality": {0, 4}, "vn1": {0, 4}, "vn2": {4, 4}}
	s := newTestSelector(nil)
	s.warmEvery = 0
	s.minHold = 0
	s.heldOut = map[string]holdRecord{"vn0": {}, "vn0-reality": {}}

	for i := range 10 {
		if s.budgetedPass(table, 2, members, reserve) {
			t.Fatalf("pass %d: failed over while a healthy member was never probed", i)
		}
	}
}

// The other side of the same rule: a tier that really is dead must still fail over
// when the budget cannot cover every member in one pass. Held-out members keep
// their verdict when skipped, so the tier becomes fully known within a pass or two.
func TestDeadTierStillFailsOverWhenBudgetCannotCoverIt(t *testing.T) {
	members := []string{"vn0", "vn0-reality", "vn1", "vn2"}
	table := map[string][2]int{"vn0": {0, 4}, "vn0-reality": {0, 4}, "vn1": {0, 4}, "vn2": {0, 4}}
	s := newTestSelector(nil)
	s.warmEvery = 0
	s.minHold = 0

	for range s.failStreak + 2 {
		if s.budgetedPass(table, 3, members, reserve) {
			return
		}
	}
	t.Fatalf("a dead tier did not fail over within %d passes", s.failStreak+2)
}

// Held-out members standing in for a blind member must not turn an unreachable
// Clash API into a failover: with nothing observed this pass, nothing is known.
func TestBlindPassWithHeldMembersHoldsTheDecision(t *testing.T) {
	s := newTestSelector(fixedProbe(nil))
	s.warmEvery = 0
	s.minHold = 0
	s.heldOut = map[string]holdRecord{"vn1": {}, "vn2": {}}
	for i := range 5 {
		if s.active(primary, reserve) {
			t.Fatalf("pass %d: failed over on a blind pass", i)
		}
	}
	if s.consecFail != 0 {
		t.Fatalf("blind passes must not build a failure streak, got %d", s.consecFail)
	}
}

// Live 2026-09-28: after vd* moved from AWG to REALITY the selector kept holding
// the AWG proxy names, which were no longer in any tier and were never probed again.
func TestHeldOutForgetsMembersThatLeaveTheTiers(t *testing.T) {
	s := newTestSelector(fixedProbe(map[string][2]int{"vn1": {0, 4}, "vn1-reality": {4, 4}}))
	s.warmEvery = 0
	s.active([]string{"vn1"}, reserve)
	if _, held := s.heldOut["vn1"]; !held {
		t.Fatalf("setup: vn1 must be held, got %v", s.heldOut)
	}
	s.active([]string{"vn1-reality"}, reserve)
	if _, held := s.heldOut["vn1"]; held {
		t.Fatalf("vn1 left every tier but is still held: %v", s.heldOut)
	}
}

// sequenceProbe answers each member from its own list of results, one per call,
// repeating the last one when the list runs out — a member that fails once and
// then answers, the way a lossy moment looks from the master.
func sequenceProbe(seq map[string][][2]int, hits map[string]int) memberProbe {
	return func(_ context.Context, name string) (int, int, error) {
		rs, ok := seq[name]
		if !ok || len(rs) == 0 {
			return 0, 0, errors.New("clash API unreachable")
		}
		i := hits[name]
		hits[name]++
		if i >= len(rs) {
			i = len(rs) - 1
		}
		return rs[i][0], rs[i][1], nil
	}
}

// Live 2026-10-28: one client's download filled a master's link, a single probe
// of an exit reached 1 of 4 destinations, and it left the rotation — a third of all
// sites moved to another exit and back a minute later. A member that fails once and
// answers the moment it is asked again was never down; it lost a race with a full
// queue. The first member sampled in a pass is re-asked before it is held out.
func TestScoutThatFailsOnceIsReaskedNotHeld(t *testing.T) {
	hits := map[string]int{}
	seq := map[string][][2]int{"vn1": {{1, 4}, {4, 4}}, "vn2": {{4, 4}}}
	s := newTestSelector(sequenceProbe(seq, hits))
	s.warmEvery = 0
	s.pass = len(primary) - 1 // the next pass starts its walk at vn1

	if s.active(primary, reserve) {
		t.Fatal("failed over on a member that answered when asked again")
	}
	if _, held := s.heldOut["vn1"]; held {
		t.Fatalf("vn1 failed once and answered on the re-ask, but was held out: %v", s.heldOut)
	}
	if hits["vn1"] != 2 {
		t.Fatalf("vn1 must be asked exactly twice (sample + re-ask), got %d", hits["vn1"])
	}
	if hits["vn2"] != 0 {
		t.Fatalf("the re-ask answered, so the walk must stop at vn1; vn2 was probed %d times", hits["vn2"])
	}
}

// The re-ask must not soften a real failure: a member that fails both times is
// held out in the same pass, exactly as before.
func TestScoutThatFailsTheReaskIsHeld(t *testing.T) {
	hits := map[string]int{}
	seq := map[string][][2]int{"vn1": {{0, 4}}, "vn2": {{4, 4}}}
	s := newTestSelector(sequenceProbe(seq, hits))
	s.warmEvery = 0
	s.pass = len(primary) - 1

	s.active(primary, reserve)
	if _, held := s.heldOut["vn1"]; !held {
		t.Fatalf("vn1 failed the sample and the re-ask but was not held: %v", s.heldOut)
	}
	if hits["vn1"] != 2 {
		t.Fatalf("vn1 must be asked twice before being held, got %d", hits["vn1"])
	}
}

// A blind re-ask (the phase budget ran out) is not evidence the member recovered:
// judge it on the sample that was actually taken.
func TestBlindReaskJudgesOnTheFirstSample(t *testing.T) {
	s := newTestSelector(nil)
	s.warmEvery = 0
	s.pass = len(primary) - 1
	s.budgetedPass(map[string][2]int{"vn1": {0, 4}, "vn2": {4, 4}}, 1, primary, reserve)
	if _, held := s.heldOut["vn1"]; !held {
		t.Fatalf("a failed sample with a blind re-ask must still hold the member: %v", s.heldOut)
	}
}
