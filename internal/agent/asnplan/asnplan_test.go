package asnplan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/asnfeed"
	"github.com/shidoh/wgfleet/internal/domain"
)

func specWith(fw domain.FirewallSpec) domain.NodeSpec { return domain.NodeSpec{Firewall: fw} }

func changes(acts []reconcile.Action) bool {
	for _, a := range acts {
		if a.Changes() {
			return true
		}
	}
	return false
}

func newTestPlanner(t *testing.T, refresh RefreshFunc) (Planner, string) {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "lib", "as-blacklist.lst")
	p := New(Config{CachePath: cache, V4URL: "http://v4", V6URL: "http://v6", Interval: time.Hour}).
		WithClock(func() time.Time { return time.Unix(2_000_000, 0) }).
		WithRefresh(refresh)
	return p, cache
}

func TestFeedOffFetchesNothing(t *testing.T) {
	p, _ := newTestPlanner(t, nil)
	acts, err := p.Plan(context.Background(), specWith(domain.FirewallSpec{}))
	if err != nil {
		t.Fatal(err)
	}
	if changes(acts) {
		t.Errorf("feed off must not refresh, got %+v", acts)
	}
}

// Observe needs the list as much as enforce does: the counter matches against it.
func TestFeedIsFetchedInBothObserveAndEnforce(t *testing.T) {
	for name, fw := range map[string]domain.FirewallSpec{
		"observe": {ASBlacklistObserve: true},
		"enforce": {ASBlacklist: true},
	} {
		t.Run(name, func(t *testing.T) {
			want := asnfeed.EncodeCache([]string{"198.51.100.0/24"}, nil, time.Unix(0, 0))
			p, cache := newTestPlanner(t, func(context.Context, string, string, time.Time) ([]byte, error) { return want, nil })

			if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), specWith(fw), reconcile.ModeApply); err != nil {
				t.Fatalf("apply: %v", err)
			}
			v4, _ := ReadCache(cache)
			if len(v4) != 1 || v4[0] != "198.51.100.0/24" {
				t.Errorf("cache after refresh = %v, want [198.51.100.0/24]", v4)
			}
		})
	}
}

// writeCache writes a cache recorded as built from urls.
func writeCache(t *testing.T, cache string, urls ...string) {
	t.Helper()
	var sources []asnfeed.SourceCount
	for _, u := range urls {
		sources = append(sources, asnfeed.SourceCount{URL: u, V4: 1, V4Addresses: 1})
	}
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	data := asnfeed.EncodeCacheWithSources([]string{"1.0.0.0/8"}, nil, sources, time.Now())
	if err := os.WriteFile(cache, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFreshCacheFromTheSameSourcesIsNotFetchedAgain(t *testing.T) {
	calls := 0
	p, cache := newTestPlanner(t, func(context.Context, string, string, time.Time) ([]byte, error) {
		calls++
		return nil, nil
	})
	p = p.WithClock(time.Now)
	writeCache(t, cache, "http://v4", "http://v6", asnfeed.ScannerListURL)
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), specWith(domain.FirewallSpec{ASBlacklist: true}), reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("a fresh cache was fetched %d times", calls)
	}
}

// After an upgrade adds a source, the cache on disk is fresh but was built
// without it. Waiting out the interval would run a day on the old list.
func TestFreshCacheFromOtherSourcesIsFetchedAtOnce(t *testing.T) {
	for name, urls := range map[string][]string{
		"written before sources were recorded": nil,
		"missing the scanner list":             {"http://v4", "http://v6"},
		"from a source no longer configured":   {"http://v4", "http://v6", asnfeed.ScannerListURL, "http://old"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			p, cache := newTestPlanner(t, func(context.Context, string, string, time.Time) ([]byte, error) {
				calls++
				return nil, errors.New("stop here")
			})
			p = p.WithClock(time.Now)
			writeCache(t, cache, urls...)
			if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), specWith(domain.FirewallSpec{ASBlacklist: true}), reconcile.ModeApply); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Errorf("fetched %d times, want 1", calls)
			}
		})
	}
}

func TestFailedFetchKeepsLastGoodAndBacksOff(t *testing.T) {
	calls := 0
	p, cache := newTestPlanner(t, func(context.Context, string, string, time.Time) ([]byte, error) {
		calls++
		return nil, errors.New("network down")
	})
	spec := specWith(domain.FirewallSpec{ASBlacklist: true})
	eng := reconcile.NewEngine(nil, p)

	if _, err := eng.Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("a failed refresh must be non-fatal, got: %v", err)
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Errorf("cache must not be written on failure")
	}
	if _, err := eng.Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("fetched %d times within the retry window, want 1", calls)
	}
}

func TestDryRunNeverFetches(t *testing.T) {
	calls := 0
	p, _ := newTestPlanner(t, func(context.Context, string, string, time.Time) ([]byte, error) {
		calls++
		return nil, nil
	})
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), specWith(domain.FirewallSpec{ASBlacklist: true}), reconcile.ModePlan); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Errorf("plan mode fetched the feed %d times", calls)
	}
}

func TestUnreadableCacheRendersEmpty(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "as-blacklist.lst")
	if err := os.WriteFile(cache, []byte("garbage line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v4, v6 := ReadCache(cache); v4 != nil || v6 != nil {
		t.Errorf("corrupt cache must read as empty, got %v %v", v4, v6)
	}
}

// Agents in the field have no extra-source key in agent.yaml; they must still
// fetch the scanner list.
func TestExtraSourcesDefaultToTheScannerList(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "as-blacklist.lst")
	for name, tc := range map[string]struct {
		extra []string
		want  bool
	}{
		"unset takes the default": {nil, true},
		"empty turns it off":      {[]string{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := New(Config{CachePath: cache, ExtraURLs: tc.extra})
			acts, err := p.Plan(context.Background(), specWith(domain.FirewallSpec{ASBlacklist: true}))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(acts[0].Display, asnfeed.ScannerListURL); got != tc.want {
				t.Errorf("plan fetches the scanner list = %v, want %v:\n%s", got, tc.want, acts[0].Display)
			}
		})
	}
}
