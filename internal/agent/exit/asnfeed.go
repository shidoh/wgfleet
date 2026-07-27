package exit

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
	"github.com/shidoh/wgfleet/internal/domain"
)

// readASBlacklistCache loads the scanner-ASN feed cache into canonical v4/v6
// prefix lists. It is deliberately best-effort: a missing or corrupt cache (the
// feed has not been fetched yet, or was torn) yields empty lists so the firewall
// renders empty sets (fail-open) rather than failing the whole reconcile.
func readASBlacklistCache(path string) (v4, v6 []string) {
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

// --- scanner-ASN blacklist feed refresh (lesson: hide exits from VPN scanners) ---

// asnFeedPlanner refreshes the scanner-ASN blacklist cache from the C24Be feeds.
// It is a feed CACHE writer, not a kernel actor: it downloads the feeds (Apply-
// side only, so dry-run never hits the network) and writes the cache file; the
// firewall planner renders that cache into the nft sets on the next pass. The
// refresh is gated on the cache file's age (the persisted last-success time) so it
// runs about once per interval, with a shorter retry window on failure so a flaky
// source is not hammered every reconcile. A failed fetch is non-fatal — the last-
// good list stays in place (fail-safe).
type asnFeedPlanner struct {
	cachePath string
	v4URL     string
	v6URL     string
	interval  time.Duration
	now       func() time.Time
	// refresh fetches+parses the feeds and returns the cache bytes to persist.
	// nil ⇒ the real asnfeed.Refresh; tests inject a stub.
	refresh func(ctx context.Context, v4URL, v6URL string, now time.Time) ([]byte, error)
}

func newASNFeedPlanner(in Input) asnFeedPlanner {
	v4 := in.ASBlacklistV4URL
	if v4 == "" {
		v4 = asnfeed.DefaultV4URL
	}
	v6 := in.ASBlacklistV6URL
	if v6 == "" {
		v6 = asnfeed.DefaultV6URL
	}
	interval := in.ASBlacklistInterval
	if interval <= 0 {
		interval = asnfeed.DefaultInterval
	}
	return asnFeedPlanner{cachePath: in.Paths.ASBlacklist, v4URL: v4, v6URL: v6, interval: interval}
}

func (asnFeedPlanner) Component() string { return "AS-blacklist feed" }

// Scheduled marks the feed refresh as out-of-band (timer-driven): its daily cache
// update is expected work, not divergence from the spec, so the drift detector
// must not count it — otherwise every refresh would WARN and bump
// agent_drift_total. See reconcile.ScheduledPlanner / Report.DriftComponents.
func (asnFeedPlanner) Scheduled() bool { return true }

// attemptPath is the marker touched on every refresh ATTEMPT (success or failure)
// so a failing source backs off to the retry window instead of refetching every
// pass. See AttemptMarkerPath.
func (p asnFeedPlanner) attemptPath() string { return AttemptMarkerPath(p.cachePath) }

func (p asnFeedPlanner) nowTime() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// retryFloor is the minimum spacing between refresh attempts after a stale cache
// is detected — bounded so it never exceeds the interval (short test intervals
// still retry promptly) and never spams a flaky source faster than hourly.
func (p asnFeedPlanner) retryFloor() time.Duration {
	if p.interval < time.Hour {
		return p.interval
	}
	return time.Hour
}

func (p asnFeedPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if !spec.Firewall.ASBlacklist {
		return []reconcile.Action{reconcile.NoChangeAction("AS-blacklist feed", "disabled")}, nil
	}
	if p.cachePath == "" {
		return []reconcile.Action{reconcile.NoChangeAction("AS-blacklist feed", "no cache path configured")}, nil
	}
	now := p.nowTime()
	if fi, err := os.Stat(p.cachePath); err == nil && now.Sub(fi.ModTime()) < p.interval {
		return []reconcile.Action{reconcile.NoChangeAction(p.cachePath, "feed fresh (within interval)")}, nil
	}
	// Cache stale or absent: refresh, unless we attempted too recently (backoff).
	if ai, err := os.Stat(p.attemptPath()); err == nil && now.Sub(ai.ModTime()) < p.retryFloor() {
		return []reconcile.Action{reconcile.NoChangeAction(p.cachePath, "feed stale; awaiting retry window")}, nil
	}
	display := fmt.Sprintf("GET %s\nGET %s", p.v4URL, p.v6URL)
	apply := func(ctx context.Context) error {
		// Record the attempt first so a failure backs off even though the cache mtime
		// (the success marker) does not advance.
		_ = os.WriteFile(p.attemptPath(), []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o644)
		refresh := p.refresh
		if refresh == nil {
			refresh = func(c context.Context, v4, v6 string, t time.Time) ([]byte, error) {
				cache, _, _, err := asnfeed.Refresh(c, &http.Client{}, v4, v6, t)
				return cache, err
			}
		}
		cache, err := refresh(ctx, p.v4URL, p.v6URL, now)
		if err != nil {
			// Non-fatal, never silent: keep the last-good list and try again next window.
			slog.Warn("AS-blacklist refresh failed (non-fatal; keeping last-good list)",
				"v4", p.v4URL, "v6", p.v6URL, "err", err)
			return nil
		}
		if err := atomicWriteFile(p.cachePath, cache, 0o644); err != nil {
			return fmt.Errorf("write AS-blacklist cache: %w", err)
		}
		slog.Info("AS-blacklist refreshed", "bytes", len(cache), "path", p.cachePath)
		return nil
	}
	return []reconcile.Action{reconcile.CustomAction(
		reconcile.ActionUpdate, p.cachePath, "refresh scanner-ASN blacklist feed", display, apply,
	)}, nil
}

// atomicWriteFile writes data to a temp file in the same dir and renames it over
// path, so a reader (the firewall planner) never sees a half-written cache.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".asnfeed-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp over %q: %w", path, err)
	}
	return nil
}
