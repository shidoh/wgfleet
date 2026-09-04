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
	// defaultHoldRecover is how many consecutive clean probes return a held-out
	// member to the normal rotating scan. It is a WATCH window, not a quarantine:
	// a clean probe has already told mihomo the member is alive again (see
	// tierUsable), so this only decides how long we keep sampling it every pass.
	defaultHoldRecover = 2
)

// memberProbe reports how many of the probe destinations `name` could reach, and
// how many were attempted. An error means the sample is untrustworthy (the Clash
// API is unreachable), NOT that the member is down.
type memberProbe func(ctx context.Context, name string) (ok, total int, err error)

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

	// heldOut are the members our probe last judged unusable, mapped to how many
	// consecutive passes have since found them usable again. They are re-probed
	// EVERY pass — see tierUsable for why that is the whole fix and not a detail.
	heldOut map[string]int
	// inRotation is the tier whose members wg-best actually routes through, as of
	// the last decision. Kept so Rotation() can answer without probing.
	inRotation []string

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
		now:           time.Now,
		heldOut:       map[string]int{},
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
	for _, m := range s.inRotation {
		_, held := s.heldOut[m]
		out[m] = held
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
	for _, m := range members {
		ok, probed, err := probe(ctx, m)
		if err != nil {
			continue // blind sample; leave it out of the tally entirely
		}
		total++
		if probed > 0 && ok >= min(s.minReachable, probed) {
			usable++
		}
	}
	s.standbyUsable, s.standbyTotal = usable, total
	if usable == 0 && total > 0 && s.log != nil {
		// Worth a warning on its own: it means a failover right now would land every
		// client on a tier that cannot reach the internet.
		s.log.Warn("standby tier has no usable member", "probed", total)
	}
}

// ReserveActive returns the tier decision for this pass: true routes wg-best to
// the reserve tier. With no reserve configured it always returns false — there is
// nowhere to fail over to, so probing would burn API calls for no decision.
func (s *TierSelector) ReserveActive(ctx context.Context, probe memberProbe, primary, reserve []string) (active bool) {
	s.pass++
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
// Held-out members are therefore re-probed FIRST and ALL of them, every pass. A
// still-failing member has its verdict re-written before mihomo's next interval,
// so our stricter judgement is the one that sticks. On a healthy tier the set is
// empty and this costs nothing — the early exit below is untouched.
func (s *TierSelector) tierUsable(ctx context.Context, probe memberProbe, members []string) (usable, known bool) {
	anyKnown, anyUsable := false, false
	for _, m := range members {
		if _, held := s.heldOut[m]; !held {
			continue
		}
		ok, total, err := probe(ctx, m)
		if err != nil {
			continue // blind: neither hold nor release on a sample we cannot trust
		}
		anyKnown = true
		if s.judge(m, ok, total) {
			anyUsable = true
		}
	}
	if anyUsable {
		return true, true
	}

	for i := range members {
		m := members[(s.pass+i)%len(members)]
		if _, held := s.heldOut[m]; held {
			continue // already re-probed above this pass
		}
		ok, total, err := probe(ctx, m)
		if err != nil {
			continue // this sample is blind; try the other members
		}
		anyKnown = true
		if s.judge(m, ok, total) {
			return true, true
		}
	}
	return false, anyKnown
}

// judge turns one member's probe result into a usable/unusable verdict and keeps
// the held-out set in step with it. Callers must not invoke it on a blind sample.
func (s *TierSelector) judge(member string, ok, total int) bool {
	need := min(s.minReachable, total)
	if total > 0 && ok >= need {
		s.release(member)
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
		s.heldOut = map[string]int{}
	}
	_, already := s.heldOut[member]
	s.heldOut[member] = 0
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
func (s *TierSelector) release(member string) {
	clean, held := s.heldOut[member]
	if !held {
		return
	}
	clean++
	if clean < s.holdRecover {
		s.heldOut[member] = clean
		return
	}
	delete(s.heldOut, member)
	if s.log != nil {
		s.log.Warn("exit returned to rotation", "exit", member, "clean_passes", clean)
	}
}
