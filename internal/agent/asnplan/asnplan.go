// Package asnplan keeps the scanner-ASN feed cache fresh and reads it back for
// the firewall renderers. Shared by both roles: exits and masters drop (or only
// count) inbound connections from the same feed.
package asnplan

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/asnfeed"
	"github.com/shidoh/wgfleet/internal/atomicfile"
	"github.com/shidoh/wgfleet/internal/domain"
)

const component = "AS-blacklist feed"

// AttemptPath is the marker touched on every refresh attempt, success or not,
// so a failing source backs off instead of being fetched every pass.
func AttemptPath(cachePath string) string { return cachePath + ".attempt" }

// ReadCache loads the feed cache into canonical v4/v6 prefix lists. Best-effort
// on purpose: a missing or corrupt cache (not fetched yet, or torn) yields empty
// lists, so the firewall renders empty sets (fail-open) instead of failing the
// whole reconcile.
func ReadCache(path string) (v4, v6 []string) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	v4, v6, err = asnfeed.DecodeCache(f)
	if err != nil {
		slog.Warn("AS-blacklist cache unreadable; rendering empty sets (fail-open)", "path", path, "err", err)
		return nil, nil
	}
	return v4, v6
}

// Config says where the cache lives and where the feed comes from. Empty URLs
// and a zero interval take the asnfeed defaults.
type Config struct {
	CachePath string
	V4URL     string
	V6URL     string
	Interval  time.Duration
}

// RefreshFunc fetches and parses the feeds and returns the cache bytes to keep.
type RefreshFunc func(ctx context.Context, v4URL, v6URL string, now time.Time) ([]byte, error)

// Planner refreshes the feed cache. It writes a file and touches nothing in the
// kernel: the download happens Apply-side only (so a dry run never hits the
// network), and the firewall planner renders the cache on the next pass. The
// refresh is gated on the cache's age, with a shorter retry window after a
// failure. A failed fetch is non-fatal: the last good list stays.
type Planner struct {
	cfg     Config
	now     func() time.Time
	refresh RefreshFunc
}

// New builds the planner, filling in the asnfeed defaults.
func New(cfg Config) Planner {
	if cfg.V4URL == "" {
		cfg.V4URL = asnfeed.DefaultV4URL
	}
	if cfg.V6URL == "" {
		cfg.V6URL = asnfeed.DefaultV6URL
	}
	if cfg.Interval <= 0 {
		cfg.Interval = asnfeed.DefaultInterval
	}
	return Planner{cfg: cfg}
}

// WithClock returns a copy that reads time from now. For tests.
func (p Planner) WithClock(now func() time.Time) Planner {
	p.now = now
	return p
}

// WithRefresh returns a copy that fetches through refresh. For tests.
func (p Planner) WithRefresh(refresh RefreshFunc) Planner {
	p.refresh = refresh
	return p
}

// Component names the planner in reconcile reports.
func (Planner) Component() string { return component }

// Scheduled marks the refresh as timer-driven: a daily cache update is expected
// work, not divergence from the spec, so the drift detector must not count it.
// See reconcile.ScheduledPlanner.
func (Planner) Scheduled() bool { return true }

func (p Planner) nowTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// retryFloor is the minimum spacing between attempts once the cache is stale:
// never longer than the interval, never faster than hourly.
func (p Planner) retryFloor() time.Duration {
	if p.cfg.Interval < time.Hour {
		return p.cfg.Interval
	}
	return time.Hour
}

// Plan refreshes the cache when the feed is in use (enforced or observed) and
// the cache is older than the interval.
func (p Planner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.Firewall.ASBlacklistActive() {
		return []reconcile.Action{reconcile.NoChangeAction(component, "disabled")}, nil
	}
	cache := p.cfg.CachePath
	if cache == "" {
		return []reconcile.Action{reconcile.NoChangeAction(component, "no cache path configured")}, nil
	}
	now := p.nowTime()
	if fi, err := os.Stat(cache); err == nil && now.Sub(fi.ModTime()) < p.cfg.Interval {
		return []reconcile.Action{reconcile.NoChangeAction(cache, "feed fresh (within interval)")}, nil
	}
	if ai, err := os.Stat(AttemptPath(cache)); err == nil && now.Sub(ai.ModTime()) < p.retryFloor() {
		return []reconcile.Action{reconcile.NoChangeAction(cache, "feed stale; awaiting retry window")}, nil
	}
	display := fmt.Sprintf("GET %s\nGET %s", p.cfg.V4URL, p.cfg.V6URL)
	return []reconcile.Action{reconcile.CustomAction(
		reconcile.ActionUpdate, cache, "refresh scanner-ASN blacklist feed", display,
		func(ctx context.Context) error { return p.apply(ctx, now) },
	)}, nil
}

func (p Planner) apply(ctx context.Context, now time.Time) error {
	cache := p.cfg.CachePath
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		return fmt.Errorf("create AS-blacklist cache dir: %w", err)
	}
	// Record the attempt first, so a failure backs off even though the cache
	// mtime (the success marker) does not move.
	if err := os.WriteFile(AttemptPath(cache), []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		slog.Warn("AS-blacklist attempt marker not written; the next pass may retry early", "err", err)
	}
	refresh := p.refresh
	if refresh == nil {
		refresh = func(c context.Context, v4, v6 string, t time.Time) ([]byte, error) {
			data, _, _, err := asnfeed.Refresh(c, &http.Client{}, v4, v6, t)
			return data, err
		}
	}
	data, err := refresh(ctx, p.cfg.V4URL, p.cfg.V6URL, now)
	if err != nil {
		slog.Warn("AS-blacklist refresh failed (non-fatal; keeping last-good list)",
			"v4", p.cfg.V4URL, "v6", p.cfg.V6URL, "err", err)
		return nil
	}
	if err := atomicfile.Write(cache, data, 0o644); err != nil {
		return fmt.Errorf("write AS-blacklist cache: %w", err)
	}
	slog.Info("AS-blacklist refreshed", "bytes", len(data), "path", cache)
	return nil
}
