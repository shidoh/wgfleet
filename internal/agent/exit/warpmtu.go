package exit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/wg"
)

// warpMTUProbeInterval is how often the auto-probe re-measures the path MTU to the
// WARP endpoint. The path is stable (datacenter ↔ Cloudflare anycast), so daily is
// plenty; a shorter retry floor handles a probe that fails (tracepath missing, etc).
const warpMTUProbeInterval = 24 * time.Hour

// readWARPMTU loads the auto-probed WARP MTU from the cache file. Best-effort: a
// missing/garbage cache returns ok=false and the caller uses the default.
func readWARPMTU(path string) (int, bool) {
	if path == "" {
		return 0, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < wg.MinTunnelMTU {
		return 0, false
	}
	return n, true
}

// effectiveWARPMTU resolves the wgcf interface MTU: the operator's explicit
// warp_mtu (spec.WARPMTU > 0) wins; otherwise the auto-probed value from the cache;
// otherwise the conservative default. Shared by the WARP-compose and MSS-clamp
// planners so both agree on one value (Plan-pure — only reads the cache file).
func effectiveWARPMTU(spec domain.NodeSpec, cachePath string) int {
	if spec.WARPMTU > 0 {
		return spec.WARPMTU
	}
	if n, ok := readWARPMTU(cachePath); ok {
		return n
	}
	return wg.DefaultWARPMTU
}

// warpMTUPlanner auto-probes the path MTU to the WARP endpoint and writes the
// derived wgcf MTU to a cache file (the asnfeed pattern). It is a cache WRITER, not
// a kernel actor: the probe runs Apply-side only (tracepath sends packets, so it
// must never run in dry-run), and the WARP/firewall planners read the cache in Plan.
// Only active on WARP exits with no explicit warp_mtu override; a failed probe is
// non-fatal and leaves the default in force.
type warpMTUPlanner struct {
	cachePath string
	endpoint  string
	interval  time.Duration
	now       func() time.Time
	// probe measures the wgcf MTU; nil ⇒ the real egress.ProbeWARPMTU (tests stub it).
	probe func(ctx context.Context, endpoint string) (int, error)
}

func newWARPMTUPlanner(in Input) warpMTUPlanner {
	return warpMTUPlanner{cachePath: in.Paths.WARPMTUCache, endpoint: egress.DefaultWARPEndpoint, interval: warpMTUProbeInterval}
}

func (warpMTUPlanner) Component() string { return "warp path-mtu probe" }

// Scheduled: the timer-driven probe is expected work, not spec divergence — keep it
// out of the drift detector (mirrors the AS-feed planner).
func (warpMTUPlanner) Scheduled() bool { return true }

func (p warpMTUPlanner) attemptPath() string { return p.cachePath + ".attempt" }

func (p warpMTUPlanner) nowTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p warpMTUPlanner) retryFloor() time.Duration {
	if p.interval < time.Hour {
		return p.interval
	}
	return time.Hour
}

func (p warpMTUPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	switch {
	case spec.Egress != domain.EgressWARP:
		return []reconcile.Action{reconcile.NoChangeAction("warp path-mtu probe", "egress not WARP")}, nil
	case spec.WARPMTU > 0:
		return []reconcile.Action{reconcile.NoChangeAction("warp path-mtu probe", "warp_mtu pinned by operator")}, nil
	case p.cachePath == "":
		return []reconcile.Action{reconcile.NoChangeAction("warp path-mtu probe", "no cache path configured")}, nil
	}
	now := p.nowTime()
	if fi, err := os.Stat(p.cachePath); err == nil && now.Sub(fi.ModTime()) < p.interval {
		return []reconcile.Action{reconcile.NoChangeAction(p.cachePath, "probe fresh (within interval)")}, nil
	}
	if ai, err := os.Stat(p.attemptPath()); err == nil && now.Sub(ai.ModTime()) < p.retryFloor() {
		return []reconcile.Action{reconcile.NoChangeAction(p.cachePath, "probe stale; awaiting retry window")}, nil
	}
	apply := func(ctx context.Context) error {
		_ = os.WriteFile(p.attemptPath(), []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o644)
		probe := p.probe
		if probe == nil {
			probe = egress.ProbeWARPMTU
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		mtu, err := probe(cctx, p.endpoint)
		if err != nil {
			// Non-fatal, never silent: the default/last-good value stays in force.
			slog.Warn("WARP path-mtu probe failed (non-fatal; using default/last-good)",
				"endpoint", p.endpoint, "default", wg.DefaultWARPMTU, "err", err)
			return nil
		}
		if err := atomicWriteFile(p.cachePath, []byte(strconv.Itoa(mtu)+"\n"), 0o644); err != nil {
			return fmt.Errorf("write warp-mtu cache: %w", err)
		}
		slog.Info("WARP path-mtu probed", "wgcf_mtu", mtu, "path", p.cachePath)
		return nil
	}
	return []reconcile.Action{reconcile.CustomAction(
		reconcile.ActionUpdate, p.cachePath, "auto-probe WARP path MTU (tracepath)",
		fmt.Sprintf("tracepath %s", p.endpoint), apply,
	)}, nil
}
