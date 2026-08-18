// Package restart throttles SELF-HEAL restarts so a service that dies instantly
// on start is not respawned forever.
//
// The reconcile loop ticks every 30s and several planners restart a service on a
// CONDITION rather than on a change: "the container is not up", "mihomo is not
// listening on its redirect port", "the WG device is duplicated". A condition
// that never clears — blocky OOM-killing on a rule-set load, xray refusing a bad
// config, mihomo unable to bind because its address is gone — makes those fire on
// every single pass. That is twice a minute, forever, burning CPU and drowning
// the log, and the restart was never going to fix it.
//
// Change-driven restarts ("the config file changed, reload") are NOT this: they
// happen once per change and are left alone.
//
// The policy keeps fast recovery for the common single crash and throttles only a
// genuine loop. Modelled on awg-manager's anti crash-loop gate (their issue #456),
// whose reasoning transfers directly.
package restart

import (
	"log/slog"
	"sync"
	"time"
)

const (
	// FreeBudget restarts inside CrashWindow run with no pause at all. The common
	// failure is one transient crash that a single restart fixes; throttling that
	// would turn a 30-second blip into minutes of downtime. Three leaves room for a
	// flaky dependency (an upstream fetch on start) without ever pausing.
	FreeBudget = 3

	// CrashWindow is the sliding window the free budget applies to. Ten minutes is
	// ~20 reconcile ticks — long enough that a real loop is unmistakable, short
	// enough that an unrelated crash hours later starts from a clean slate.
	CrashWindow = 10 * time.Minute

	// BackoffBase is the first pause once the budget is spent; each further
	// over-budget attempt doubles it.
	BackoffBase = 1 * time.Minute

	// BackoffCap bounds the doubling. Fifteen minutes still retries a few times an
	// hour, so a service whose cause disappears (memory freed, network back,
	// upstream reachable) self-heals without anyone logging in — while costing
	// nothing when it does not.
	BackoffCap = 15 * time.Minute

	// HealthyRun is how long a service must go WITHOUT needing a restart before it
	// stops counting as part of a loop. Past this the counters reset and the next
	// crash gets the full free budget again, so one bad afternoon does not leave a
	// punitive pause armed for the rest of the week.
	HealthyRun = 30 * time.Minute
)

// entry is one key's restart history.
type entry struct {
	// recent holds the restart times still inside CrashWindow, oldest first.
	recent []time.Time
	// last is the most recent restart, zero if none. Kept separately from recent
	// because the healthy-run reset must survive the window pruning.
	last time.Time
	// pause is the current backoff, doubling per over-budget attempt. Zero until
	// the budget is first exceeded.
	pause time.Duration
	// until is when a suppressed key may restart again.
	until time.Time
}

// Governor decides whether a self-heal restart may run. It is safe for concurrent
// use and MUST outlive a reconcile pass: planners are rebuilt every tick, so a
// governor constructed inside one would forget every restart it ever saw and the
// throttle would never engage. Hold it on the agent and pass it in, exactly as the
// exit-tier selector is held.
type Governor struct {
	mu    sync.Mutex
	state map[string]*entry
	log   *slog.Logger
	now   func() time.Time // overridden in tests
}

// New returns a Governor. A nil logger is fine — suppressions are then silent.
func New(log *slog.Logger) *Governor {
	return &Governor{state: map[string]*entry{}, log: log, now: time.Now}
}

// Allow reports whether a self-heal restart of key may run now. When it may not,
// the second return is the time it will be allowed again.
//
// A nil Governor allows everything: "not wired up" must mean "behave exactly as
// before", never "silently stop self-healing".
func (g *Governor) Allow(key string) (bool, time.Time) {
	if g == nil {
		return true, time.Time{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	e := g.entryLocked(key, now)
	if e.until.IsZero() || !now.Before(e.until) {
		return true, time.Time{}
	}
	return false, e.until
}

// Record notes that a restart of key was applied. Call it from the action's apply
// path, never at plan time — a dry run must not consume budget.
func (g *Governor) Record(key string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	e := g.entryLocked(key, now)
	e.recent = append(e.recent, now)
	e.last = now

	if len(e.recent) < FreeBudget {
		// Still inside the free budget. Deliberately does NOT clear an existing
		// backoff: the crash window (10m) is shorter than the longest pause (15m),
		// so a service parked at the cap would have its window prune itself empty
		// between retries and win back a full free budget every time — the throttle
		// would unwind exactly for the services it exists to throttle. Only a
		// genuine healthy run (see entryLocked) resets the level.
		return
	}
	// Budget spent: arm (or double) the pause, so the NEXT restart has to wait.
	// The comparison is >= rather than >: FreeBudget counts the restarts that run
	// freely, so once that many have happened inside the window the following one
	// is already over budget.
	if e.pause == 0 {
		e.pause = BackoffBase
	} else if e.pause < BackoffCap {
		if e.pause *= 2; e.pause > BackoffCap {
			e.pause = BackoffCap
		}
	}
	e.until = now.Add(e.pause)
	if g.log != nil {
		g.log.Warn("restart throttled: this service keeps needing a self-heal restart",
			"key", key, "restarts_in_window", len(e.recent), "pause", e.pause, "until", e.until)
	}
}

// entryLocked returns key's entry with the crash window pruned and the healthy-run
// reset applied. Caller holds mu.
func (g *Governor) entryLocked(key string, now time.Time) *entry {
	if g.state == nil {
		g.state = map[string]*entry{}
	}
	e := g.state[key]
	if e == nil {
		e = &entry{}
		g.state[key] = e
	}
	// A long quiet stretch means the service is not looping — forget everything.
	if !e.last.IsZero() && now.Sub(e.last) >= HealthyRun {
		*e = entry{}
		return e
	}
	cutoff := now.Add(-CrashWindow)
	kept := e.recent[:0]
	for _, t := range e.recent {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.recent = kept
	return e
}
