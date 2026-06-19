package health

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Throughput watchdog defaults. Demotion is faster than recovery so a transient
// dip doesn't pull an exit out, but a flapping path doesn't bounce back in either
// (mirrors the egress failover Selector's asymmetric hysteresis, ADR-0017).
const (
	// DefaultThroughputDegradeAfter is the consecutive below-floor probes before
	// the watchdog reports the egress throughput-degraded.
	DefaultThroughputDegradeAfter = 3
	// DefaultThroughputRecoverAfter is the consecutive at-or-above-floor probes
	// before the watchdog clears the degraded state.
	DefaultThroughputRecoverAfter = 2
	// DefaultThroughputProbeURL downloads ~256 KiB from Cloudflare's speed endpoint.
	// It is enough to separate a throttled path (tens of KB/s) from a healthy one
	// (MB/s) while costing little data. Routing this through WARP still exposes a
	// throttled exit (verified live: exit-3 stalled fetching it via wgcf). Override
	// per fleet for a stricter, non-Cloudflare target.
	DefaultThroughputProbeURL = "https://speed.cloudflare.com/__down?bytes=262144"
)

// ThroughputProbe measures the egress throughput in bytes/sec, or returns an
// error if the measurement could not be taken at all. A throttled-but-reachable
// path returns a low rate with no error (the watchdog thresholds it); only a
// total failure to measure is an error.
type ThroughputProbe func(ctx context.Context) (bytesPerSec float64, err error)

// NewThroughputProbe builds the real throughput probe: it downloads url through
// iface (empty ⇒ default route) and returns the achieved bytes/sec. Exported so
// the agent can build one for the active egress (the watchdog) and a separate one
// for wgcf (the failover recovery probe, which must test the preferred egress's
// throughput, not just its reachability).
func NewThroughputProbe(iface, url string) ThroughputProbe { return throughputProbe(iface, url) }

// throughputProbe downloads url through iface (empty ⇒ default route, e.g. direct
// egress) and returns the achieved bytes/sec. It tolerates a max-time abort: curl
// still reports the partial size_download/time_total, which for a throttled path
// is exactly the low rate we want to detect — so a timeout is a slow result, not
// an error. Only an unparseable/empty result (connect failure) is an error.
func throughputProbe(iface, url string) ThroughputProbe {
	if url == "" {
		url = DefaultThroughputProbeURL
	}
	return func(ctx context.Context) (float64, error) {
		args := []string{"-s", "-o", "/dev/null", "-w", "%{size_download} %{time_total}",
			"--max-time", strconv.Itoa(int(probeTimeout.Seconds()))}
		if iface != "" {
			args = append(args, "--interface", iface)
		}
		args = append(args, url)
		// Ignore the exit code: a --max-time abort (exit 28) on a throttled path still
		// prints a valid "size time" line on stdout, which is the slow rate we want.
		out, _ := exec.CommandContext(ctx, "curl", args...).Output()
		rate, ok := parseThroughput(string(out))
		if !ok {
			return 0, fmt.Errorf("throughput probe via %q produced no measurement", ifaceOrDefault(iface))
		}
		return rate, nil
	}
}

func ifaceOrDefault(iface string) string {
	if iface == "" {
		return "default route"
	}
	return iface
}

// parseThroughput parses curl's "<size_download> <time_total>" write-out into a
// bytes/sec rate. A zero or missing time yields no measurement (false).
func parseThroughput(out string) (float64, bool) {
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 2 {
		return 0, false
	}
	size, err1 := strconv.ParseFloat(fields[0], 64)
	secs, err2 := strconv.ParseFloat(fields[1], 64)
	if err1 != nil || err2 != nil || secs <= 0 {
		return 0, false
	}
	return size / secs, true
}

// ThroughputWatchdog turns a sequence of throughput measurements into a stable
// "egress throughput-degraded" signal with asymmetric hysteresis. It distinguishes
// a sustained throttle (which mihomo's latency-only url-test cannot see) from a
// one-off dip. Hold one instance per agent; Observe mutates the streak.
type ThroughputWatchdog struct {
	// MinBytesPerSec is the throughput floor. Observe must not be called when this
	// is <= 0 (watchdog disabled); the agent gates on it.
	MinBytesPerSec float64
	// DegradeAfter / RecoverAfter override the defaults when > 0 (tests use small values).
	DegradeAfter int
	RecoverAfter int

	bad, good int
	degraded  bool
	lastRate  float64
}

// LastBytesPerSec returns the most recent measured egress throughput (0 before the
// first Observe or on a probe error), for the agent's rate gauge.
func (w *ThroughputWatchdog) LastBytesPerSec() float64 { return w.lastRate }

// Observe runs the probe, updates the streak, and returns whether the egress is
// (now) throughput-degraded plus the self-check to report (CheckEgressThroughput).
// The check's OK mirrors the smoothed degraded state, so the controller reads one
// boolean; Detail carries the last measured rate and the streak.
func (w *ThroughputWatchdog) Observe(ctx context.Context, probe ThroughputProbe) (bool, domain.HealthCheck) {
	degradeAfter := w.DegradeAfter
	if degradeAfter <= 0 {
		degradeAfter = DefaultThroughputDegradeAfter
	}
	recoverAfter := w.RecoverAfter
	if recoverAfter <= 0 {
		recoverAfter = DefaultThroughputRecoverAfter
	}

	rate, err := probe(ctx)
	w.lastRate = rate
	healthy := err == nil && rate >= w.MinBytesPerSec

	var measured string
	if err != nil {
		measured = "probe error: " + err.Error()
	} else {
		measured = fmt.Sprintf("%s (min %s)", kbPerSec(rate), kbPerSec(w.MinBytesPerSec))
	}

	if healthy {
		w.good++
		w.bad = 0
		if w.good >= recoverAfter {
			w.degraded = false
		}
	} else {
		w.bad++
		w.good = 0
		if w.bad >= degradeAfter {
			w.degraded = true
		}
	}

	detail := measured
	if w.degraded {
		detail = "throughput-degraded: " + measured
	} else if !healthy {
		detail = fmt.Sprintf("below floor (%d/%d): %s", w.bad, degradeAfter, measured)
	}
	return w.degraded, domain.HealthCheck{
		Name:   domain.CheckEgressThroughput,
		OK:     !w.degraded,
		Detail: detail,
	}
}

// kbPerSec formats a bytes/sec rate as a human KB/s string.
func kbPerSec(bps float64) string {
	return fmt.Sprintf("%.0f KB/s", bps/1024)
}
