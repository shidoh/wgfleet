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
)

// memberProbe reports how many of the probe destinations `name` could reach, and
// how many were attempted. An error means the sample is untrustworthy (the Clash
// API is unreachable), NOT that the member is down.
type memberProbe func(ctx context.Context, name string) (ok, total int, err error)

// tierSelector decides whether the master routes to the reserve tier, with
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
type tierSelector struct {
	log *slog.Logger

	failStreak    int
	recoverStreak int
	minHold       time.Duration
	minReachable  int
	now           func() time.Time

	// state carried across reconcile passes
	reserveActive bool
	consecFail    int
	consecOK      int
	lastFlip      time.Time
}

func newTierSelector(log *slog.Logger) *tierSelector {
	return &tierSelector{
		log:           log,
		failStreak:    defaultTierFailStreak,
		recoverStreak: defaultTierRecoverStreak,
		minHold:       defaultTierMinHold,
		minReachable:  defaultMinReachable,
		now:           time.Now,
	}
}

// ReserveActive returns the tier decision for this pass: true routes wg-best to
// the reserve tier. With no reserve configured it always returns false — there is
// nowhere to fail over to, so probing would burn API calls for no decision.
func (s *tierSelector) ReserveActive(ctx context.Context, probe memberProbe, primary, reserve []string) bool {
	if len(reserve) == 0 || len(primary) == 0 {
		// Nothing to choose between. Reset the streaks so a later reserve tier starts
		// from a clean slate rather than inheriting a stale count.
		s.consecFail, s.consecOK = 0, 0
		s.reserveActive = false
		return false
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
func (s *tierSelector) flip(toReserve bool, why string) {
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
func (s *tierSelector) tierUsable(ctx context.Context, probe memberProbe, members []string) (usable, known bool) {
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
