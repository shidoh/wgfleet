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

// BridgeStallAfter is how long a bridge socket may go without receiving a byte
// before the watchdog kills it. The portal sends a mux keepalive every ~10 s, so
// a live flow always grows; 30 s is three missed keepalives.
const BridgeStallAfter = 30 * time.Second

// BridgeWatchdogInterval is how often the watchdog looks at the bridge sockets.
const BridgeWatchdogInterval = 5 * time.Second

// bridgeCmdTimeout bounds one ss invocation.
const bridgeCmdTimeout = 5 * time.Second

// BridgeWatchdog kills a reverse-bridge socket (ADR-0038) whose received byte
// count has stopped growing. A flow frozen one way — data from the master
// dropped, bare ACKs passing — stays ESTABLISHED on both ends: measured, neither
// keepalive nor TCP_USER_TIMEOUT on either end notices it, and traffic came back
// only ~100 s after the path did. Killing the socket makes xray redial on a fresh
// flow; measured, traffic was back in 31 s while the old flow was still frozen.
type BridgeWatchdog struct {
	log    *slog.Logger
	bridge func() *domain.RealityBridgeSpec
	run    func(ctx context.Context, name string, args ...string) (string, error)
	now    func() time.Time

	mu    sync.Mutex
	seen  map[bridgeSock]sockProgress
	kills map[string]uint64
}

type bridgeSock struct{ local, peer netip.AddrPort }

type sockProgress struct {
	bytes  uint64
	since  time.Time
	killed bool
}

// NewBridgeWatchdog returns a watchdog over the bridge bridge() reports; nil
// means the exit is not in the mode and the watchdog does nothing.
func NewBridgeWatchdog(log *slog.Logger, bridge func() *domain.RealityBridgeSpec) *BridgeWatchdog {
	return &BridgeWatchdog{
		log:    log,
		bridge: bridge,
		run:    runSS,
		now:    time.Now,
		seen:   map[bridgeSock]sockProgress{},
		kills:  map[string]uint64{},
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

// Tick looks at the bridge sockets once and kills the ones that stalled.
func (w *BridgeWatchdog) Tick(ctx context.Context) {
	bridge := w.bridge()
	w.mu.Lock()
	defer w.mu.Unlock()
	if bridge == nil {
		clear(w.seen)
		return
	}
	portals := health.PortalMasters(bridge)
	out, err := w.run(ctx, "ss", "-tniH", "state", "established")
	if err != nil {
		w.log.Warn("bridge watchdog: ss failed; not judging sockets this tick", "err", err)
		return
	}
	now := w.now()
	current := map[bridgeSock]bool{}
	for _, s := range health.ParseSSEstablished(out) {
		master, ok := portals[s.Peer]
		if !ok {
			continue
		}
		key := bridgeSock{local: s.Local, peer: s.Peer}
		current[key] = true
		prev, known := w.seen[key]
		if !known || s.BytesReceived != prev.bytes {
			w.seen[key] = sockProgress{bytes: s.BytesReceived, since: now}
			continue
		}
		if prev.killed || now.Sub(prev.since) < BridgeStallAfter {
			continue
		}
		w.kill(ctx, master, key, now.Sub(prev.since))
		prev.killed = true
		w.seen[key] = prev
	}
	for key := range w.seen {
		if !current[key] {
			delete(w.seen, key)
		}
	}
}

func (w *BridgeWatchdog) kill(ctx context.Context, master string, s bridgeSock, stalled time.Duration) {
	_, err := w.run(ctx, "ss", "-K",
		"dst", s.peer.Addr().String(), "dport", "=", strconv.Itoa(int(s.peer.Port())),
		"sport", "=", ":"+strconv.Itoa(int(s.local.Port())))
	if err != nil {
		w.log.Warn("bridge watchdog: could not kill a stalled socket", "master", master,
			"local", s.local.String(), "portal", s.peer.String(), "err", err)
		return
	}
	w.kills[master]++
	w.log.Warn("bridge watchdog: killed a socket that received nothing; xray redials", "master", master,
		"local", s.local.String(), "portal", s.peer.String(), "stalled", stalled.Round(time.Second))
}

func runSS(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, bridgeCmdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}
