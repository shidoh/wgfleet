package exit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

func newWARPTestPlanner(t *testing.T, now time.Time, probe func(context.Context, string) (int, error)) warpMTUPlanner {
	t.Helper()
	return warpMTUPlanner{
		cachePath: filepath.Join(t.TempDir(), "warp-mtu"),
		endpoint:  "engage.cloudflareclient.com:2408",
		interval:  24 * time.Hour,
		now:       func() time.Time { return now },
		probe:     probe,
	}
}

func planWARP(t *testing.T, p warpMTUPlanner, spec domain.NodeSpec) []reconcile.Action {
	t.Helper()
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return acts
}

func warpSpec() domain.NodeSpec { return domain.NodeSpec{Egress: domain.EgressWARP} }

// TestWARPMTUOperatorPinBeatsTheProbe. warp_mtu is the knob an operator reaches
// for precisely when the auto-probe got it wrong — pinning 1380 is what cured a
// live WARP black hole once. If the probe ever started running (and later
// overwriting the cache) while a pin is set, it would quietly undo a deliberate
// fix and the exit would black-hole full-size packets again.
func TestWARPMTUOperatorPinBeatsTheProbe(t *testing.T) {
	probed := false
	p := newWARPTestPlanner(t, time.Now(), func(context.Context, string) (int, error) {
		probed = true
		return 1280, nil
	})
	spec := warpSpec()
	spec.WARPMTU = 1380

	acts := planWARP(t, p, spec)
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("a pinned warp_mtu must produce no work, got %+v", acts)
	}
	if !strings.Contains(acts[0].Summary, "pinned") {
		t.Errorf("summary %q should say the operator pinned it", acts[0].Summary)
	}
	if probed {
		t.Error("the probe must not run at all when the operator pinned warp_mtu")
	}
}

// TestWARPMTUNotProbedOffWARP — a non-WARP exit has no WARP path to measure, and
// running tracepath at it every pass would be pure noise.
func TestWARPMTUNotProbedOffWARP(t *testing.T) {
	probed := false
	p := newWARPTestPlanner(t, time.Now(), func(context.Context, string) (int, error) { probed = true; return 1280, nil })
	acts := planWARP(t, p, domain.NodeSpec{Egress: domain.EgressDirect})
	if acts[0].Changes() || probed {
		t.Errorf("non-WARP egress must not probe: acts=%+v probed=%v", acts, probed)
	}
}

// TestWARPMTUFailedProbeKeepsLastGood is the black-hole guard. A probe that fails
// (tracepath blocked, endpoint unreachable) must leave the cached value alone: the
// exit keeps running on the last measured MTU. Clobbering or truncating the cache
// here would drop the node back to the default and re-open the PMTU black hole the
// cache exists to prevent — and it would do so silently, because a failed probe is
// deliberately non-fatal.
func TestWARPMTUFailedProbeKeepsLastGood(t *testing.T) {
	now := time.Now()
	p := newWARPTestPlanner(t, now, func(context.Context, string) (int, error) {
		return 0, errors.New("tracepath: no reply")
	})
	if err := os.WriteFile(p.cachePath, []byte("1340\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Make the cache stale so the probe actually runs.
	old := now.Add(-48 * time.Hour)
	if err := os.Chtimes(p.cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	acts := planWARP(t, p, warpSpec())
	if len(acts) != 1 || !acts[0].Changes() {
		t.Fatalf("a stale cache must schedule a probe, got %+v", acts)
	}
	if _, err := reconcile.NewEngine(nil, stubPlanner{acts}).Reconcile(context.Background(), warpSpec(), reconcile.ModeApply); err != nil {
		t.Fatalf("a failed probe must stay non-fatal, got: %v", err)
	}
	if got := readCache(t, p.cachePath); got != "1340" {
		t.Errorf("cache = %q after a failed probe, want the last-good 1340 untouched", got)
	}
}

// TestWARPMTUFailedProbeArmsTheRetryFloor — the attempt marker must be stamped
// even when the probe fails, because that marker is what throttles the retry. If
// it were only written on success, a permanently failing probe would run tracepath
// on every 30s reconcile pass forever.
func TestWARPMTUFailedProbeArmsTheRetryFloor(t *testing.T) {
	now := time.Now()
	calls := 0
	p := newWARPTestPlanner(t, now, func(context.Context, string) (int, error) {
		calls++
		return 0, errors.New("unreachable")
	})
	spec := warpSpec()

	acts := planWARP(t, p, spec)
	if _, err := reconcile.NewEngine(nil, stubPlanner{acts}).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("probe ran %d times on the first pass, want 1", calls)
	}
	// Immediately after, the next pass must back off rather than probe again.
	next := planWARP(t, p, spec)
	if next[0].Changes() {
		t.Fatalf("a probe that just failed must not run again immediately, got %+v", next)
	}
	if !strings.Contains(next[0].Summary, "retry") {
		t.Errorf("summary %q should explain the retry window", next[0].Summary)
	}
}

// TestWARPMTUFreshCacheIsNotReprobed — the probe is a 24h measurement, not a
// per-pass one; re-running tracepath every 30s would be a self-inflicted DoS on
// the WARP endpoint.
func TestWARPMTUFreshCacheIsNotReprobed(t *testing.T) {
	now := time.Now()
	p := newWARPTestPlanner(t, now, func(context.Context, string) (int, error) {
		t.Error("a fresh cache must not be re-probed")
		return 0, nil
	})
	if err := os.WriteFile(p.cachePath, []byte("1340\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	acts := planWARP(t, p, warpSpec())
	if acts[0].Changes() {
		t.Errorf("fresh cache must produce no work, got %+v", acts)
	}
}

// TestWARPMTUSuccessfulProbeUpdatesCache — the happy path still has to land.
func TestWARPMTUSuccessfulProbeUpdatesCache(t *testing.T) {
	now := time.Now()
	p := newWARPTestPlanner(t, now, func(context.Context, string) (int, error) { return 1352, nil })
	acts := planWARP(t, p, warpSpec())
	if _, err := reconcile.NewEngine(nil, stubPlanner{acts}).Reconcile(context.Background(), warpSpec(), reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if got := readCache(t, p.cachePath); got != "1352" {
		t.Errorf("cache = %q, want the probed 1352", got)
	}
}

func readCache(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// stubPlanner replays a pre-built action list through the engine so the apply
// closures run exactly as they would in production.
type stubPlanner struct{ acts []reconcile.Action }

func (stubPlanner) Component() string { return "warp path-mtu probe" }
func (s stubPlanner) Plan(context.Context, domain.NodeSpec) ([]reconcile.Action, error) {
	return s.acts, nil
}
