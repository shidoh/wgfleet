package exit

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
	"github.com/shidoh/wgfleet/internal/domain"
)

// BridgeStallAfter is how long a bridge socket may go without receiving data
// before the watchdog kills it. The portal sends a mux keepalive every ~10 s, so
// a live flow never goes this long; 30 s is three missed keepalives.
const BridgeStallAfter = 30 * time.Second

// BridgeWatchdogInterval is how often the watchdog looks at the bridge sockets.
const BridgeWatchdogInterval = 5 * time.Second

// bridgeCmdTimeout bounds one ss invocation.
const bridgeCmdTimeout = 5 * time.Second

// BridgeWatchdog kills a reverse-bridge socket (ADR-0038) that has received
// nothing for BridgeStallAfter, by the kernel's own lastrcv. A flow frozen one
// way — data from the master dropped, bare ACKs passing — stays ESTABLISHED on
// both ends: measured, neither keepalive nor TCP_USER_TIMEOUT on either end
// notices it, and traffic came back only ~100 s after the path did. Killing the
// socket makes xray redial on a fresh flow. lastrcv, not a byte count: a flow
// frozen from its first segment has received nothing to count (seen on the
// stand), and lastrcv needs no history across ticks.
type BridgeWatchdog struct {
	log    *slog.Logger
	bridge func() *domain.RealityBridgeSpec
	run    func(ctx context.Context, name string, args ...string) (string, error)
	now    func() time.Time

	mu       sync.Mutex
	killedAt map[bridgeSock]time.Time
	kills    map[string]uint64
}

type bridgeSock struct{ local, peer netip.AddrPort }

// NewBridgeWatchdog returns a watchdog over the bridge bridge() reports; nil
// means the exit is not in the mode and the watchdog does nothing.
func NewBridgeWatchdog(log *slog.Logger, bridge func() *domain.RealityBridgeSpec) *BridgeWatchdog {
	return &BridgeWatchdog{
		log:      log,
		bridge:   bridge,
		run:      runSS,
		now:      time.Now,
		killedAt: map[bridgeSock]time.Time{},
		kills:    map[string]uint64{},
	}
}

// Run ticks until ctx ends.
func (w *BridgeWatchdog) Run(ctx context.Context) {
	t := time.NewTicker(BridgeWatchdogInterval)
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

// Kills returns how many sockets were killed per master since start: an early
// indicator of freezes on that master's path.
func (w *BridgeWatchdog) Kills() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return maps.Clone(w.kills)
}

// Tick looks at the bridge sockets once and kills the ones that stalled. ss runs
// outside the lock so a slow one never holds up a metrics scrape.
func (w *BridgeWatchdog) Tick(ctx context.Context) {
	bridge := w.bridge()
	if bridge == nil {
		w.mu.Lock()
		clear(w.killedAt)
		w.mu.Unlock()
		return
	}
	portals := health.PortalMasters(bridge)
	out, err := w.run(ctx, "ss", "-tniH", "state", "established")
	if err != nil {
		w.log.Warn("bridge watchdog: ss failed; not judging sockets this tick", "err", err)
		return
	}
	type stalled struct {
		master string
		sock   bridgeSock
		silent time.Duration
	}
	var kill []stalled
	now := w.now()
	w.mu.Lock()
	current := map[bridgeSock]bool{}
	for _, s := range health.ParseSSEstablished(out) {
		master, ok := portals[s.Peer]
		// Without lastrcv there is nothing to judge.
		if !ok || !s.HasLastRcv {
			continue
		}
		key := bridgeSock{local: s.Local, peer: s.Peer}
		current[key] = true
		if s.LastRcv < BridgeStallAfter {
			continue
		}
		// Killed already: give the kill a stall interval before trying again.
		if at, done := w.killedAt[key]; done && now.Sub(at) < BridgeStallAfter {
			continue
		}
		w.killedAt[key] = now
		kill = append(kill, stalled{master, key, s.LastRcv})
	}
	for key := range w.killedAt {
		if !current[key] {
			delete(w.killedAt, key)
		}
	}
	w.mu.Unlock()
	for _, k := range kill {
		w.kill(ctx, k.master, k.sock, k.silent)
	}
}
func (w *BridgeWatchdog) kill(ctx context.Context, master string, s bridgeSock, stalled time.Duration) {
	_, err := w.run(ctx, "ss", "-K",
		"dst", s.peer.Addr().String(), "dport", "=", ":"+strconv.Itoa(int(s.peer.Port())),
		"sport", "=", ":"+strconv.Itoa(int(s.local.Port())))
	if err != nil {
		w.log.Warn("bridge watchdog: could not kill a stalled socket", "master", master,
			"local", s.local.String(), "portal", s.peer.String(), "err", err)
		return
	}
	w.mu.Lock()
	w.kills[master]++
	w.mu.Unlock()
	w.log.Warn("bridge watchdog: killed a socket that received nothing; xray redials", "master", master,
		"local", s.local.String(), "portal", s.peer.String(), "stalled", stalled.Round(time.Second))
}

func runSS(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, bridgeCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
