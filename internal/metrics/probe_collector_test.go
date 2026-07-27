package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// touchAt creates path and stamps it with an exact mtime, so the exported
// timestamps are deterministic.
func touchAt(t *testing.T, path string, unix int64) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(unix, 0)
	if err := os.Chtimes(path, ts, ts); err != nil {
		t.Fatal(err)
	}
}

func newProbeReg(t *testing.T, probes []Probe) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	NewProbeCollector(reg, "exit-de-1", "exit", probes)
	return reg
}

const probeMetricNames = "wgfleet_probe_last_success_timestamp_seconds wgfleet_probe_last_attempt_timestamp_seconds"

// The regression this whole collector exists for: the probe attempts on schedule
// and fails every single time, so the cache is never written. Attempts advance
// while last-success stays 0 — visible instead of silent.
func TestProbeCollectorAttemptedButNeverSucceeded(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "warp-mtu")
	touchAt(t, cache+".attempt", 1_700_000_500)

	reg := newProbeReg(t, []Probe{{Name: "warp_path_mtu", SuccessPath: cache, AttemptPath: cache + ".attempt"}})

	want := `
# HELP wgfleet_probe_last_attempt_timestamp_seconds Unix time of a scheduled probe's last run attempt, successful or not; 0 means it has never run.
# TYPE wgfleet_probe_last_attempt_timestamp_seconds gauge
wgfleet_probe_last_attempt_timestamp_seconds{node="exit-de-1",probe="warp_path_mtu",role="exit"} 1.7000005e+09
# HELP wgfleet_probe_last_success_timestamp_seconds Unix time of a scheduled probe's last SUCCESSFUL run; 0 means it has never succeeded.
# TYPE wgfleet_probe_last_success_timestamp_seconds gauge
wgfleet_probe_last_success_timestamp_seconds{node="exit-de-1",probe="warp_path_mtu",role="exit"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), strings.Fields(probeMetricNames)...); err != nil {
		t.Error(err)
	}
}

func TestProbeCollectorHealthyProbe(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "as-blacklist.lst")
	touchAt(t, cache, 1_700_000_000)
	touchAt(t, cache+".attempt", 1_700_000_000)

	reg := newProbeReg(t, []Probe{{Name: "as_blacklist_feed", SuccessPath: cache, AttemptPath: cache + ".attempt"}})

	want := `
# HELP wgfleet_probe_last_attempt_timestamp_seconds Unix time of a scheduled probe's last run attempt, successful or not; 0 means it has never run.
# TYPE wgfleet_probe_last_attempt_timestamp_seconds gauge
wgfleet_probe_last_attempt_timestamp_seconds{node="exit-de-1",probe="as_blacklist_feed",role="exit"} 1.7e+09
# HELP wgfleet_probe_last_success_timestamp_seconds Unix time of a scheduled probe's last SUCCESSFUL run; 0 means it has never succeeded.
# TYPE wgfleet_probe_last_success_timestamp_seconds gauge
wgfleet_probe_last_success_timestamp_seconds{node="exit-de-1",probe="as_blacklist_feed",role="exit"} 1.7e+09
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), strings.Fields(probeMetricNames)...); err != nil {
		t.Error(err)
	}
}

// A probe that does not apply on this node (feature off, warp_mtu pinned) has no
// markers at all. It must yield NO series: an all-zero pair would read as broken.
func TestProbeCollectorSilentWhenProbeNeverRan(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "warp-mtu")

	reg := newProbeReg(t, []Probe{{Name: "warp_path_mtu", SuccessPath: cache, AttemptPath: cache + ".attempt"}})

	if n := testutil.CollectAndCount(reg); n != 0 {
		t.Errorf("series for a probe that never ran = %d, want 0", n)
	}
}

// Marker files are optional inputs, not scrape dependencies: a stale cache with a
// vanished attempt marker (tmpfs cleared, /run wiped) must still report the last
// known success rather than dropping the probe off the dashboard.
func TestProbeCollectorSucceededButAttemptMarkerGone(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "warp-mtu")
	touchAt(t, cache, 1_700_000_000)

	reg := newProbeReg(t, []Probe{{Name: "warp_path_mtu", SuccessPath: cache, AttemptPath: cache + ".attempt"}})

	want := `
# HELP wgfleet_probe_last_attempt_timestamp_seconds Unix time of a scheduled probe's last run attempt, successful or not; 0 means it has never run.
# TYPE wgfleet_probe_last_attempt_timestamp_seconds gauge
wgfleet_probe_last_attempt_timestamp_seconds{node="exit-de-1",probe="warp_path_mtu",role="exit"} 0
# HELP wgfleet_probe_last_success_timestamp_seconds Unix time of a scheduled probe's last SUCCESSFUL run; 0 means it has never succeeded.
# TYPE wgfleet_probe_last_success_timestamp_seconds gauge
wgfleet_probe_last_success_timestamp_seconds{node="exit-de-1",probe="warp_path_mtu",role="exit"} 1.7e+09
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), strings.Fields(probeMetricNames)...); err != nil {
		t.Error(err)
	}
}

func TestProbeCollectorIgnoresIncompleteProbes(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "warp-mtu")
	touchAt(t, cache, 1_700_000_000)

	reg := newProbeReg(t, []Probe{
		{Name: "", SuccessPath: cache, AttemptPath: cache + ".attempt"},
		{Name: "no_path", SuccessPath: "", AttemptPath: ""},
	})
	if n := testutil.CollectAndCount(reg); n != 0 {
		t.Errorf("series from incomplete probe specs = %d, want 0", n)
	}
}
