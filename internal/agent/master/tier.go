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
	now           func() time.Time

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
		now:           time.Now,
	}
}

// StandbyHealth reports the last warm-probe result for the inactive tier: how many
// of its members were usable, out of how many were probed. total == 0 means it has
// not been sampled yet.
func (s *TierSelector) StandbyHealth() (usable, total int) {
	return s.standbyUsable, s.standbyTotal
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
func (s *TierSelector) ReserveActive(ctx context.Context, probe memberProbe, primary, reserve []string) bool {
	s.pass++
	if len(reserve) == 0 || len(primary) == 0 {
		// Nothing to choose between. Reset the streaks so a later reserve tier starts
		// from a clean slate rather than inheriting a stale count.
		s.consecFail, s.consecOK = 0, 0
		s.reserveActive = false
		return false
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
func (s *TierSelector) tierUsable(ctx context.Context, probe memberProbe, members []string) (usable, known bool) {
	anyKnown := false
	for _, m := range members {
		ok, total, err := probe(ctx, m)
		if err != nil {
			continue // this sample is blind; try the other members
		}
		anyKnown = true
		need := min(s.minReachable, total)
		if total > 0 && ok >= need {
			return true, true
		}
		if s.log != nil {
			s.log.Info("exit failed multi-destination probe", "exit", m, "reachable", ok, "probed", total)
		}
	}
	return false, anyKnown
}
