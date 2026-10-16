// Package sockwatch kills established TCP sockets that have gone silent for too
// long by the kernel's own clocks (`ss -tni`), so the program owning them redials
// on a fresh flow. Both ends of the exit-initiated REALITY link (ADR-0038) need
// it: a flow frozen one way stays ESTABLISHED on both ends, and neither keepalive
// nor TCP_USER_TIMEOUT got rid of it in measurements.
package sockwatch

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/health"
)

// Interval is how often a watchdog looks at the socket table.
const Interval = 5 * time.Second

// cmdTimeout bounds one ss invocation.
const cmdTimeout = 5 * time.Second

// Matcher says whether a socket is watched, under which label (counted per
// label), and how long it has been silent by the criterion that matters for it.
type Matcher func(s health.SSSocket) (label string, silent time.Duration, watched bool)

// Watchdog kills watched sockets silent for StallAfter or longer.
type Watchdog struct {
	log        *slog.Logger
	what       string
	stallAfter time.Duration
	// matcher returns the current Matcher, nil when there is nothing to watch.
	matcher func() Matcher
	run     func(ctx context.Context, name string, args ...string) (string, error)
	now     func() time.Time

	mu       sync.Mutex
	killedAt map[sock]time.Time
	kills    map[string]uint64
}

type sock struct{ local, peer netip.AddrPort }

// Option configures a Watchdog.
type Option func(*Watchdog)

// WithRunner replaces the command runner (tests).
func WithRunner(run func(ctx context.Context, name string, args ...string) (string, error)) Option {
	return func(w *Watchdog) { w.run = run }
}

// WithClock replaces the clock (tests).
func WithClock(now func() time.Time) Option {
	return func(w *Watchdog) { w.now = now }
}

// New returns a watchdog; what names it in the log.
func New(log *slog.Logger, what string, stallAfter time.Duration, matcher func() Matcher, opts ...Option) *Watchdog {
	w := &Watchdog{
		log: log, what: what, stallAfter: stallAfter, matcher: matcher,
		run: runCmd, now: time.Now,
		killedAt: map[sock]time.Time{}, kills: map[string]uint64{},
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Run ticks until ctx ends.
func (w *Watchdog) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// Kills returns how many sockets were killed per label since start.
func (w *Watchdog) Kills() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return maps.Clone(w.kills)
}

// Tick looks at the socket table once and kills the stalled sockets. ss runs
// outside the lock so a slow one never holds up a metrics scrape.
func (w *Watchdog) Tick(ctx context.Context) {
	match := w.matcher()
	if match == nil {
		w.mu.Lock()
		clear(w.killedAt)
		w.mu.Unlock()
		return
	}
	out, err := w.run(ctx, "ss", "-tniH", "state", "established")
	if err != nil {
		w.log.Warn(w.what+": ss failed; not judging sockets this tick", "err", err)
		return
	}
	type stalled struct {
		label  string
		s      sock
		silent time.Duration
	}
	var kill []stalled
	now := w.now()
	w.mu.Lock()
	current := map[sock]bool{}
	for _, s := range health.ParseSSEstablished(out) {
		label, silent, watched := match(s)
		if !watched {
			continue
		}
		key := sock{local: s.Local, peer: s.Peer}
		current[key] = true
		if silent < w.stallAfter {
			continue
		}
		// Killed already: give the kill a stall interval before trying again.
		if at, done := w.killedAt[key]; done && now.Sub(at) < w.stallAfter {
			continue
		}
		w.killedAt[key] = now
		kill = append(kill, stalled{label, key, silent})
	}
	for key := range w.killedAt {
		if !current[key] {
			delete(w.killedAt, key)
		}
	}
	w.mu.Unlock()
	for _, k := range kill {
		w.kill(ctx, k.label, k.s, k.silent)
	}
}

func (w *Watchdog) kill(ctx context.Context, label string, s sock, silent time.Duration) {
	_, err := w.run(ctx, "ss", "-K",
		"dst", s.peer.Addr().String(), "dport", "=", ":"+strconv.Itoa(int(s.peer.Port())),
		"sport", "=", ":"+strconv.Itoa(int(s.local.Port())))
	if err != nil {
		w.log.Warn(w.what+": could not kill a stalled socket", "peer_label", label,
			"local", s.local.String(), "peer", s.peer.String(), "err", err)
		return
	}
	w.mu.Lock()
	w.kills[label]++
	w.mu.Unlock()
	w.log.Warn(w.what+": killed a silent socket; the peer redials", "peer_label", label,
		"local", s.local.String(), "peer", s.peer.String(), "silent", silent.Round(time.Second))
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
