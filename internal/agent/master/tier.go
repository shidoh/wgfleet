package master

import (
	"context"
	"log/slog"
	"time"
)

// Tier-selection defaults. Deliberately asymmetric: leaving the primary tier is
// cheap to get wrong (the reserve is presumed usable), coming back is expensive
// (returning to a still-broken primary re-breaks every client), so recovery
// demands more consecutive evidence than failure does.
const (
	// defaultTierFailStreak is how many consecutive passes must find the primary
	// tier unusable before failing over.
	defaultTierFailStreak = 2
	// defaultTierRecoverStreak is how many consecutive passes must find it usable
	// again before failing back.
	defaultTierRecoverStreak = 4
	// defaultTierMinHold is the minimum time between flips. The hard floor on churn:
	// each flip rewrites config.yaml and reloads mihomo, and a reload resets every
	// group's health state — so a flapping exit could otherwise drive a feedback loop
	// where instability causes reloads and reloads deepen instability (observed
	// 2026-07-19: 22 reloads in a day while the fleet was sick).
	defaultTierMinHold = 10 * time.Minute
	// defaultMinReachable is how many probe destinations a member must reach to
	// count as usable. Above 1 on purpose: a member that answers exactly one
	// destination is the signature of a destination-scoped block, not of health.
	defaultMinReachable = 2
	// defaultWarmEvery is how often (in reconcile passes) the INACTIVE tier is
	// probed. At the 30s reconcile interval this is once a minute.
	//
	// It exists because the flat-group rendering (ADR-0029 rev 2) leaves the
	// inactive tier's proxies configured but in no group, so mihomo never dials
	// them. Observed live 2026-07-19: within ~1.5h of the cutover the only AWG
	// reserve exit went Degraded on `wg-handshake — stale handshake (1h23m45s
	// old)` while every other check passed. Two problems, and the second is the
	// real one:
	//
	//  1. An idle reserve exit LOOKS broken, which is noise at best and blocks a
	//     rolling update at worst (its gate requires Ready).
	//  2. The reserve goes COLD. WireGuard re-handshakes about every 2 minutes
	//     under traffic; with no traffic the tunnel must be built from scratch at
	//     the exact moment failover needs it — latency added precisely when it
	//     hurts. A warm standby that is only warm on paper is not a standby.
	//
	// Probing the inactive tier fixes both and, as a bonus, is the only source of
	// health data about the tier we would fail over TO — without it that decision
	// is made blind.
	defaultWarmEvery = 2
	// defaultStandbyEvery is how often (in reconcile passes) the STANDBY TRANSPORTS
	// are probed — the inactive half of a dual-transport exit (ADR-0025), which is
	// drained on purpose and therefore in no tier, so nothing else ever dials it.
	//
	// Much rarer than defaultWarmEvery, and for a different reason. Warming the
	// standby TIER is about keeping tunnels hot for a failover that happens on its
	// own; this is about knowing whether the transport an operator would switch to
	// works at all. Once every 10 passes (5 minutes at the 30s cadence) answers that
	// while keeping a path we deliberately keep quiet quiet: it carries no traffic,
	// so every probe on it is pure cost.
	//
	// Measured live 2026-09-04: five of six exits had a standby transport and none
	// had ever been health-checked. Four reported alive=1 — mihomo's default for an
	// untested proxy, not a measurement — so the fleet showed a confident green on
	// no evidence at all, and the fifth was frozen on an 82-minute-old verdict.
	// ADR-0025's plan item 6 promised "per-transport reachability"; the
	// active-transport metric shipped and this half did not.
	defaultStandbyEvery = 10
	// defaultHoldRecover is how many consecutive clean probes return a held-out
	// member to the normal rotating scan. It is a WATCH window, not a quarantine:
	// a clean probe has already told mihomo the member is alive again (see
	// tierUsable), so this only decides how long we keep sampling it every pass.
	defaultHoldRecover = 2
)

// memberProbe reports how many of the probe destinations `name` could reach, and
// how many were attempted. An error means the sample is untrustworthy (the Clash
// API is unreachable, or the phase had no budget left to ask), NOT that the member
// is down. Every caller here must treat a non-nil error as "hold the current
// verdict" — judging on it is how a member nobody asked ends up out of rotation.
//
// The ctx passed per call may be ignored by the implementation: budgetedProbe (the
// production one) substitutes its own, because handing a probe a deadline that can
// expire mid-flight is what evicts healthy exits from wg-best.
type memberProbe func(ctx context.Context, name string) (ok, total int, err error)

// holdRecord is what we know about a member we are holding out: the probe result
// that produced the verdict, when the spell began, and how many consecutive clean
// probes it has answered since (the counter release() walks back to zero).
type holdRecord struct {
	clean     int
	reachable int
	probed    int
	since     time.Time
}

// ExitVerdict is the master's own judgement on one exit of the tier that carries
// traffic — the cause behind an exit vanishing from the load balancer, in the
// three facts an operator asks for in that order: is it out, on what evidence,
// and since when.
type ExitVerdict struct {
	HeldOut bool
	// Reachable/Probed are the last multi-destination probe result. Probed == 0
	// means this member has not been sampled since it was last judged healthy —
	// the walk stops at the first usable member, so a green tier leaves most of its
	// members unprobed on most passes. Absent evidence, not evidence of health.
	Reachable int
	Probed    int
	// Since is when the current hold began, NOT when it was last re-confirmed. Zero
	// when the member is not held out.
	Since time.Time
}

// TierSelector decides whether the master routes to the reserve tier, with
// hysteresis so a flapping exit cannot churn the data plane.
//
// It exists because mihomo cannot make this decision itself: a `fallback` group
// over nested `load-balance` tiers reduces "is the tier up" to "is one hash-picked
// member up", and real client failures never reach the parent's choice (see
// mihomo.wgBestGroups). Moving the decision here also lets it rest on evidence a
// single lightweight probe cannot produce — reachability across several
// independent destinations, which is what exposes a censored-but-"healthy" exit.
//
// Not safe for concurrent use; the reconcile loop is single-threaded per pass.
type TierSelector struct {
	log *slog.Logger

	failStreak    int
	recoverStreak int
	minHold       time.Duration
	minReachable  int
	warmEvery     int
	holdRecover   int
	now           func() time.Time

	// heldOut are the members our probe last judged unusable, mapped to the
	// substance of that verdict. They are re-probed EVERY pass — see tierUsable for
	// why that is the whole fix and not a detail.
	heldOut map[string]holdRecord
	// inRotation is the tier whose members wg-best actually routes through, as of
	// the last decision. Kept so Rotation() can answer without probing.
	inRotation []string
	// standbyTransport is the last verdict per standby-transport proxy: can it
	// reach enough destinations. Absent ⇒ never sampled.
	standbyTransport map[string]bool
	standbyEvery     int

	// state carried across reconcile passes
	reserveActive bool
	consecFail    int
	consecOK      int
	lastFlip      time.Time
	pass          int
	// standbyUsable/standbyTotal are the last warm-probe result for the INACTIVE
	// tier: how many of its members could reach enough destinations. Without this
	// the failover decision is one-sided — we would know the active tier is dying
	// but nothing about the tier we are about to move every client onto.
	standbyUsable int
	standbyTotal  int
	// standbyMember is the same warm probe kept PER MEMBER. The tally above cannot
	// be acted on: one dead reserve exit hides inside "2 of 3 usable", so nothing
	// alerts and nothing names it until the last one dies too.
	standbyMember map[string]ExitVerdict
}

func NewTierSelector(log *slog.Logger) *TierSelector {
	return &TierSelector{
		log:           log,
		failStreak:    defaultTierFailStreak,
		recoverStreak: defaultTierRecoverStreak,
		minHold:       defaultTierMinHold,
		minReachable:  defaultMinReachable,
		warmEvery:     defaultWarmEvery,
		holdRecover:   defaultHoldRecover,
		standbyEvery:  defaultStandbyEvery,
		now:           time.Now,
		heldOut:       map[string]holdRecord{},
	}
}

// StandbyHealth reports the last warm-probe result for the inactive tier: how many
// of its members were usable, out of how many were probed. total == 0 means it has
// not been sampled yet.
func (s *TierSelector) StandbyHealth() (usable, total int) {
	return s.standbyUsable, s.standbyTotal
}

// ReserveIsActive reads the last tier decision. It takes no decision and runs no
// probe — the reconcile pass owns that; this is for reporting.
func (s *TierSelector) ReserveIsActive() bool { return s.reserveActive }

// ProbeStandbyTransports keeps a verdict on each STANDBY transport: the inactive
// half of a dual-transport exit, drained on purpose and therefore in no tier, so
// no other probe in this file ever reaches it (see defaultStandbyEvery for what
// that cost on the live fleet).
//
// It is deliberately NOT part of any decision. Nothing here fails over on a
// standby's condition — the switch is the operator's, by explicit design
// (ADR-0025: "no auto-failover") — so this only answers the question that
// decision needs and that nothing else could answer: does the path we would move
// this exit onto work.
//
// Writing mihomo's `alive` as a side effect of probing, which is what made a
// failing exit flap out of the load balancer, is harmless here for the one reason
// that matters: a standby proxy is in no group, so its alive flag steers nothing.
//
// members is the CURRENT standby set (mihomo.StandbyProxies); anything absent
// from it is forgotten rather than left frozen at its last verdict.
func (s *TierSelector) ProbeStandbyTransports(ctx context.Context, probe memberProbe, members []string) {
	if len(members) == 0 {
		s.standbyTransport = nil
		return
	}
	// Drop exits that no longer have a standby before the cadence check, so a
	// vanished one stops being reported immediately rather than at the next probe.
	kept := make(map[string]bool, len(members))
	for _, m := range members {
		if v, ok := s.standbyTransport[m]; ok {
			kept[m] = v
		}
	}
	s.standbyTransport = kept

	if s.standbyEvery <= 0 || s.pass%s.standbyEvery != 0 {
		return
	}
	for _, m := range members {
		ok, total, err := probe(ctx, m)
		if err != nil {
			continue // blind: keep whatever we last knew rather than inventing a failure
		}
		usable := total > 0 && ok >= min(s.minReachable, total)
		if was, seen := s.standbyTransport[m]; s.log != nil && (!seen || was != usable) {
			// Logged as "proxy", not "exit": a standby's proxy name always carries the
			// transport suffix, so calling it an exit prints a node that does not exist.
			// The metric does the join and labels the real node.
			if usable {
				s.log.Info("standby transport usable", "proxy", m, "reachable", ok, "probed", total)
			} else {
				// Worth a warning on its own: the fallback this exit is supposed to have
				// is not there, and the switch that needs it is an emergency action.
				s.log.Warn("standby transport unusable — switching to it would not restore this exit",
					"proxy", m, "reachable", ok, "probed", total)
			}
		}
		s.standbyTransport[m] = usable
	}
}

// StandbyTransportHealth reports the last verdict per standby-transport proxy.
// An absent entry means never sampled, which is NOT the same as healthy — the
// distinction the live fleet lost when four untested proxies reported alive=1.
func (s *TierSelector) StandbyTransportHealth() map[string]bool {
	out := make(map[string]bool, len(s.standbyTransport))
	for k, v := range s.standbyTransport {
		out[k] = v
	}
	return out
}

// Rotation reports, for each exit in the tier that currently carries traffic,
// whether our multi-destination verdict is holding it out of the load balancer.
// Empty before the first decision.
//
// It covers the ACTIVE tier only. An idle reserve member is not in the group at
// all, so "held out" says nothing about it, and publishing one would invite an
// alert on an exit that carries no traffic by design.
//
// This is the only place the verdict is legible from outside. mihomo's own view —
// exported by the controller as wgfleet_exit_tunnel_alive — shows the effect, an
// exit gone from the balancer, but never which of the two health criteria put it
// there.
func (s *TierSelector) Rotation() map[string]bool {
	out := make(map[string]bool, len(s.inRotation))
	for m, v := range s.RotationVerdicts() {
		out[m] = v.HeldOut
	}
	return out
}

// RotationVerdicts is Rotation() with the evidence attached: for every exit in the
// tier that carries traffic, whether we are holding it out, on what probe result,
// and since when. The agent puts it in the status report, so the console can say
// WHY an exit stopped carrying instead of only that it did — the question the
// journal on the master answered and nothing else could.
func (s *TierSelector) RotationVerdicts() map[string]ExitVerdict {
	out := make(map[string]ExitVerdict, len(s.inRotation))
	for _, m := range s.inRotation {
		rec, held := s.heldOut[m]
		out[m] = ExitVerdict{
			HeldOut:   held,
			Reachable: rec.reachable,
			Probed:    rec.probed,
			Since:     rec.since,
		}
	}
	return out
}

// warmStandby probes the currently INACTIVE tier so its tunnels stay established
// and its health is known. Its result never feeds the tier decision — that would
// couple "should we leave the active tier" to the standby's condition, which is a
// different question — but it is logged and exposed via StandbyHealth.
func (s *TierSelector) warmStandby(ctx context.Context, probe memberProbe, members []string) {
	if len(members) == 0 || s.warmEvery <= 0 || s.pass%s.warmEvery != 0 {
		return
	}
	usable, total := 0, 0
	// Rebuilt from this sweep, not merged into the old map: a member that has left
	// the reserve tier must stop being reported rather than freeze at its last
	// verdict, the same rule ProbeStandbyTransports follows.
	perMember := make(map[string]ExitVerdict, len(members))
	for _, m := range members {
		ok, probed, err := probe(ctx, m)
		if err != nil {
			continue // blind sample; leave it out of the tally entirely
		}
		total++
		// HeldOut stays false on purpose. This member is in no rotation, so there is
		// no rotation to be held out of; what we have is evidence, not a verdict.
		perMember[m] = ExitVerdict{Reachable: ok, Probed: probed}
		if probed > 0 && ok >= min(s.minReachable, probed) {
			usable++
		}
	}
	s.standbyUsable, s.standbyTotal = usable, total
	s.standbyMember = perMember
	if usable == 0 && total > 0 && s.log != nil {
		// Worth a warning on its own: it means a failover right now would land every
		// client on a tier that cannot reach the internet.
		s.log.Warn("standby tier has no usable member", "probed", total)
	}
}

// StandbyVerdicts reports the last warm-probe result for each member of the idle
// tier, by name. Empty before the first warm sweep; a member absent from it was
// not sampled, which is not the same as healthy.
//
// It is what turns "the standby tier is 2 of 3 usable" — a number nobody can act
// on — into an exit an operator can go and look at.
func (s *TierSelector) StandbyVerdicts() map[string]ExitVerdict {
	out := make(map[string]ExitVerdict, len(s.standbyMember))
	for k, v := range s.standbyMember {
		out[k] = v
	}
	return out
}

// StandbyMemberHealth is StandbyVerdicts reduced to the pass/fail the metric and
// the alert read: did this member reach enough destinations to count as usable.
func (s *TierSelector) StandbyMemberHealth() map[string]bool {
	out := make(map[string]bool, len(s.standbyMember))
	for k, v := range s.standbyMember {
		out[k] = v.Probed > 0 && v.Reachable >= min(s.minReachable, v.Probed)
	}
	return out
}

// ReserveActive returns the tier decision for this pass: true routes wg-best to
// the reserve tier. With no reserve configured it always returns false — there is
// nowhere to fail over to, so probing would burn API calls for no decision.
func (s *TierSelector) ReserveActive(ctx context.Context, probe memberProbe, primary, reserve []string) (active bool) {
	s.pass++
	s.forgetDeparted(primary, reserve)
	// Record which tier this decision puts in front of client traffic, at whichever
	// of the several exits below we leave by. Rotation() then answers without
	// probing — a metrics read must never burn Clash API calls or move hysteresis.
	defer func() {
		if active {
			s.inRotation = reserve
			return
		}
		s.inRotation = primary
	}()
	if len(reserve) == 0 {
		// Nowhere to fail over to. Reset the streaks so a reserve tier added later
		// starts from a clean slate rather than inheriting a stale count.
		s.consecFail, s.consecOK = 0, 0
		s.reserveActive = false
		return false
	}
	if len(primary) == 0 {
		// Primary is STARVED, not merely unhealthy — every member is drained
		// (ADR-0010), so there is nothing left to probe and nothing to decide.
		//
		// This must report the RESERVE, not the primary. wgBestGroups falls back to
		// whatever tier is non-empty, so an empty primary already puts live traffic on
		// the reserve; returning false here would make the selector's own view of
		// where traffic goes disagree with what it just rendered. That divergence is
		// not cosmetic — warmStandby uses it to pick which tier to keep warm, so the
		// selector would warm the tier that is actually carrying traffic and leave the
		// idle one to go cold, i.e. exactly backwards.
		//
		// Streaks reset because there is no primary health signal to accumulate; when
		// primary members return, the normal recovery streak governs the way back.
		s.consecFail, s.consecOK = 0, 0
		s.reserveActive = true
		return true
	}

	// Keep the reserve tier warm while it is idle. The flat group leaves its proxies
	// in no group, so nothing else ever dials them (see defaultWarmEvery). Only when
	// the reserve is INACTIVE: once it is carrying traffic it is warm by definition,
	// and the primary is then probed every pass anyway as the recovery check.
	if !s.reserveActive {
		defer func() { s.warmStandby(ctx, probe, reserve) }()
	}

	// Which tier's health decides the next move: while on reserve we are asking
	// "can we go home yet?", so we probe the primary either way.
	usable, known := s.tierUsable(ctx, probe, primary)
	if !known {
		// Unreachable API: hold the current decision. Flipping on a blind sample is
		// how a control-plane hiccup turns into a data-plane outage.
		return s.reserveActive
	}

	if usable {
		s.consecOK++
		s.consecFail = 0
	} else {
		s.consecFail++
		s.consecOK = 0
	}
	if s.log != nil {
		s.log.Debug("tier decision", "primary_usable", usable, "reserve_active", s.reserveActive,
			"consec_fail", s.consecFail, "consec_ok", s.consecOK, "held_out", len(s.heldOut))
	}

	switch {
	case !s.reserveActive && s.consecFail >= s.failStreak:
		s.flip(true, "primary tier unusable")
	case s.reserveActive && s.consecOK >= s.recoverStreak:
		s.flip(false, "primary tier recovered")
	}
	return s.reserveActive
}

// flip changes tiers unless the minimum hold since the last flip has not elapsed.
func (s *TierSelector) flip(toReserve bool, why string) {
	if !s.lastFlip.IsZero() && s.now().Sub(s.lastFlip) < s.minHold {
		if s.log != nil {
			s.log.Info("tier flip suppressed by min-hold",
				"want_reserve", toReserve, "why", why,
				"since_last_flip", s.now().Sub(s.lastFlip).Truncate(time.Second),
				"min_hold", s.minHold)
		}
		return
	}
	s.reserveActive = toReserve
	s.lastFlip = s.now()
	s.consecFail, s.consecOK = 0, 0
	if s.log != nil {
		s.log.Warn("exit tier switched", "reserve_active", toReserve, "why", why)
	}
}

// tierUsable reports whether ANY member of the tier can reach enough destinations.
// One healthy member is enough: mihomo balances across whatever remains, so a tier
// is "down" only when every member is. known=false means the probe could not be
// taken at all and the caller must not act on the result.
//
// The walk STARTS AT A ROTATING OFFSET. Stopping at the first usable member is what
// keeps the probe cheap on a healthy tier, but starting at index 0 every time meant
// members[0] absorbed the entire probe load forever while the rest were never
// sampled. Measured live 2026-07-19/20: vn1 took ~5 samples per 30s cycle against
// vn2's 1, and vn1's latency spread was 27ms (90-117) versus vn2's 1ms (96-97) — in
// the same datacentre off the same floor. The "vn1/vn2 latency spike" chased all
// evening as a network fault was substantially self-inflicted probe contention.
// Rotating spreads the load without giving up the early exit.
// A verdict here is not just an observation, and that is the part the original
// version of this function missed. `GET /proxies/{name}/delay` — how ProbeMember
// asks the question — RECORDS its result in mihomo and flips the proxy's `alive`
// flag, which is exactly what removes a member from a load-balance group.
// Verified against the live master 2026-09-04: probing a reserve proxy at an
// unroutable address turned alive false, probing it at cp.cloudflare.com turned it
// back true.
//
// So this probe and the group's own health check write the SAME flag under
// DIFFERENT criteria — ours across four independent destinations, mihomo's against
// one lightweight URL every `interval`. Ours evicts a censored or dead exit;
// mihomo's revives it on the weaker test. Whoever wrote last wins, and the early
// exit meant a failing member often went several passes unprobed, so mihomo won
// almost every time: measured on the live fleet, 27 failed verdicts in 13 days
// (vn2 x13, vn0 x9, vn1 x5) and a broken exit that flapped in and out of rotation
// instead of leaving it.
//
// Held-out members are therefore re-probed ALL of them, every pass — right after
// one member of the live rotation (see below for why not before it). A
// still-failing member has its verdict re-written before mihomo's next interval,
// so our stricter judgement is the one that sticks. On a healthy tier the set is
// empty and this costs nothing — the early exit is untouched.
func (s *TierSelector) tierUsable(ctx context.Context, probe memberProbe, members []string) (usable, known bool) {
	var free, held []string
	for i := range members {
		m := members[(s.pass+i)%len(members)]
		if _, isHeld := s.heldOut[m]; isHeld {
			held = append(held, m)
		} else {
			free = append(free, m)
		}
	}

	// A member the phase budget never reached is UNKNOWN, not down. Counting it as
	// down is how the live fleet failed over on 2026-09-28 without vn2 ever being
	// asked. A skipped held-out member keeps its standing verdict instead — it was
	// judged unusable and nothing since says otherwise — which is what still lets a
	// genuinely dead tier fail over when one pass cannot cover every member.
	anyKnown, anyUsable, freeBlind := false, false, false
	sample := func(m string, isHeld, reask bool) bool {
		ok, total, err := probe(ctx, m)
		if err != nil {
			if !isHeld {
				freeBlind = true
			}
			return false
		}
		anyKnown = true
		if reask && !s.reaches(ok, total) {
			ok, total = s.reaskOnce(ctx, probe, m, ok, total)
		}
		return s.judge(m, ok, total)
	}

	// One member of the live rotation goes FIRST. Held-out members are usually dead
	// and each burns a whole probe timeout; asked first, two of them exhausted the
	// phase budget every pass, the healthy members were never sampled, and the
	// recovery streak reset forever (live, 2026-09-28). A healthy member answers in
	// milliseconds, so going first costs the held-out re-probe almost nothing.
	//
	// This first member — the scout — is the only one re-asked before being held out
	// (see reaskOnce). Members walked AFTER a failed scout are not: by then the tier
	// itself looks sick, and a second timeout per member would only slow the failover
	// a dead tier needs.
	if len(free) > 0 {
		anyUsable = sample(free[0], false, true)
		free = free[1:]
	}
	for _, m := range held {
		if sample(m, true, false) {
			anyUsable = true
		}
	}
	if anyUsable {
		return true, true
	}
	for _, m := range free {
		if sample(m, false, false) {
			return true, true
		}
	}
	return false, anyKnown && !freeBlind
}

// reaches reports whether a probe result counts as usable: enough destinations
// answered, with the threshold clamped to how many were actually tried.
func (s *TierSelector) reaches(ok, total int) bool {
	return total > 0 && ok >= min(s.minReachable, total)
}

// reaskOnce probes a member that has just failed one more time and returns the
// result to judge it on.
//
// One failed sample is weak evidence and the price of acting on it is high. Live
// 2026-10-28: a single client's download filled a master's link, one probe of an exit
// reached 1 of 4 destinations, and the exit left the rotation. wg-best hashes sites to
// exits, so a third of all sites moved to another exit — and moved back when the
// next pass found it fine. Every session pinned to an exit's address broke twice.
// A member that answers the moment it is asked again was never down; it lost a race
// with a full queue.
//
// The re-ask also undoes the damage of the first one: the failed `delay` call has
// already written alive=false into mihomo, and a passing one writes it back within
// seconds instead of leaving the exit out until the next pass.
//
// A blind re-ask (the phase is out of budget) is not evidence of recovery, so the
// member is judged on the sample that was actually taken.
func (s *TierSelector) reaskOnce(ctx context.Context, probe memberProbe, m string, ok, total int) (int, int) {
	ok2, total2, err := probe(ctx, m)
	if err != nil {
		return ok, total
	}
	if s.reaches(ok2, total2) && s.log != nil {
		s.log.Info("exit failed one probe and answered the re-ask; kept in rotation",
			"exit", m, "first", ok, "of", total, "reask", ok2, "reask_of", total2)
	}
	return ok2, total2
}

// forgetDeparted drops held-out records for members that are in neither tier any
// more — a transport switch renames every proxy, and the old names were otherwise
// held (and counted) forever without ever being probed again.
func (s *TierSelector) forgetDeparted(primary, reserve []string) {
	current := make(map[string]bool, len(primary)+len(reserve))
	for _, m := range primary {
		current[m] = true
	}
	for _, m := range reserve {
		current[m] = true
	}
	for m := range s.heldOut {
		if !current[m] {
			delete(s.heldOut, m)
		}
	}
}

// judge turns one member's probe result into a usable/unusable verdict and keeps
// the held-out set in step with it. Callers must not invoke it on a blind sample.
func (s *TierSelector) judge(member string, ok, total int) bool {
	if s.reaches(ok, total) {
		s.release(member, ok, total)
		return true
	}
	s.hold(member, ok, total)
	return false
}

// hold records that the member is out of rotation. The first pass of a spell is a
// WARNING because it is a data-plane change — this exit stops carrying client
// traffic — and nothing else in the system says so out loud.
func (s *TierSelector) hold(member string, ok, total int) {
	if s.heldOut == nil {
		s.heldOut = map[string]holdRecord{}
	}
	prev, already := s.heldOut[member]
	// The stamp survives a re-confirmation: it is when this spell BEGAN. Re-stamping
	// every failing pass would make every hold read as seconds old no matter how
	// long it had been running, which is the one number that decides whether an
	// operator waits it out or goes looking.
	since := prev.since
	if !already || since.IsZero() {
		since = s.now()
	}
	s.heldOut[member] = holdRecord{reachable: ok, probed: total, since: since}
	if s.log == nil {
		return
	}
	if already {
		s.log.Info("held-out exit still failing", "exit", member, "reachable", ok, "probed", total)
		return
	}
	s.log.Warn("exit held out of rotation", "exit", member, "reachable", ok, "probed", total)
}

// release walks a recovering member back to the normal rotating scan once it has
// answered cleanly holdRecover times running. It does NOT gate the member's return
// to traffic: the clean probe that got us here already told mihomo it is alive.
func (s *TierSelector) release(member string, ok, total int) {
	rec, held := s.heldOut[member]
	if !held {
		return
	}
	rec.clean++
	rec.reachable, rec.probed = ok, total
	if rec.clean < s.holdRecover {
		s.heldOut[member] = rec
		return
	}
	delete(s.heldOut, member)
	if s.log != nil {
		s.log.Warn("exit returned to rotation", "exit", member, "clean_passes", rec.clean)
	}
}
