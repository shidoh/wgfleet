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
	// throttled exit (a throttled exit stalls fetching it via wgcf). Override
	// per fleet for a stricter, non-Cloudflare target.
	DefaultThroughputProbeURL = "https://speed.cloudflare.com/__down?bytes=262144"
	// probeRangeBytes bounds every probe download to the same 256 KiB, whatever the
	// file behind the URL is: the alternates below are 1 MB files served with
	// Range support, and a probe that downloaded all of it would cost four times
	// the data for the same answer.
	probeRangeBytes = 262144
)

// DefaultThroughputProbeURLs are the targets the watchdog tries IN ORDER, stopping
// at the first that clears the floor.
//
// One target is not a bandwidth measurement, it is a measurement of that target.
// An exit can be declared throughput-degraded repeatedly when
// speed.cloudflare.com alone answers its 256 KiB slowly (hundreds of ms to seconds,
// below the 250 KiB/s floor) while other CDNs, through the SAME WARP tunnel and the
// SAME egress address, answer in tens of milliseconds at megabytes per second. TCP
// and TLS to Cloudflare complete quickly; the delay is that endpoint deciding when
// to start sending. Every verdict built on it — the check, the controller's
// auto-suspend, the reload cascade behind it — is then a verdict about a speed-test
// page. Spread across independent operators, like the exit-reachability probe.
var DefaultThroughputProbeURLs = []string{
	DefaultThroughputProbeURL,
	"https://cachefly.cachefly.net/1mb.test",
	"https://proof.ovh.net/files/1Mb.dat",
}

// ThroughputProbe measures the egress throughput in bytes/sec, or returns an
// error if the measurement could not be taken at all. A throttled-but-reachable
// path returns a low rate with no error (the watchdog thresholds it); only a
// total failure to measure is an error.
type ThroughputProbe func(ctx context.Context) (bytesPerSec float64, err error)

// NewThroughputProbe builds the real throughput probe: it downloads through iface
// (empty ⇒ default route) from the given targets in order and returns the best
// bytes/sec it saw, stopping at the first that clears floor. An explicit override
// URL (the fleet's egress_throughput_probe_url) replaces the default list rather
// than joining it: an operator who names a target means that target. Exported so
// the agent can build one for the active egress (the watchdog) and a separate one
// for wgcf (the failover recovery probe, which must test the preferred egress's
// throughput, not just its reachability).
func NewThroughputProbe(iface, override string, floor float64) ThroughputProbe {
	urls := DefaultThroughputProbeURLs
	if override != "" {
		urls = []string{override}
	}
	return func(ctx context.Context) (float64, error) {
		return probeBest(ctx, floor, urls, func(ctx context.Context, url string) (float64, error) {
			return throughputProbe(iface, url)(ctx)
		})
	}
}

// probeBest is the target-selection half, free of curl so it is testable: try the
// targets in order, return the first rate at or above floor, otherwise the best
// rate seen; an error only when NO target produced a measurement. Sequential on
// purpose — concurrent downloads on a genuinely 2 Mbit path would each read a
// third of it and fail a healthy exit — and the early exit keeps the common case
// at one download.
func probeBest(ctx context.Context, floor float64, urls []string, measure func(ctx context.Context, url string) (float64, error)) (float64, error) {
	var (
		best     float64
		measured bool
		firstErr error
	)
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		rate, err := measure(ctx, u)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		measured = true
		if rate >= floor && floor > 0 {
			return rate, nil
		}
		if rate > best {
			best = rate
		}
	}
	if !measured {
		if firstErr == nil {
			firstErr = fmt.Errorf("throughput probe: no targets")
		}
		return 0, firstErr
	}
	return best, nil
}

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
			"--max-time", strconv.Itoa(int(probeTimeout.Seconds())),
			// Same 256 KiB from every target; a server without Range support simply
			// sends the whole file, which is what the Cloudflare URL already sizes.
			"-r", "0-" + strconv.Itoa(probeRangeBytes-1)}
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

// Observe decides health from the BEST evidence of throughput and updates the
// streak. passiveBytesPerSec is the real traffic already moving on the active
// egress this pass (rx+tx delta / elapsed, measured by the agent); probe is a lazy
// active download. A link saturated by legitimate client traffic proves itself
// passively, so the active probe is SKIPPED for it — that avoids falsely degrading
// a busy-but-healthy exit (the probe would lose the bandwidth race and read low,
// the false-positive the operator flagged). The probe runs ONLY when real traffic
// is below the floor, i.e. on an idle/under-floor link where it is uncontended and
// accurate. healthy = max(passive, probe) >= floor. Returns whether the egress is
// (now) throughput-degraded plus the self-check to report (CheckEgressThroughput).
func (w *ThroughputWatchdog) Observe(ctx context.Context, passiveBytesPerSec float64, probe ThroughputProbe) (bool, domain.HealthCheck) {
	degradeAfter := w.DegradeAfter
	if degradeAfter <= 0 {
		degradeAfter = DefaultThroughputDegradeAfter
	}
	recoverAfter := w.RecoverAfter
	if recoverAfter <= 0 {
		recoverAfter = DefaultThroughputRecoverAfter
	}

	rate := passiveBytesPerSec
	detail := fmt.Sprintf("live %s", kbPerSec(passiveBytesPerSec))
	if rate < w.MinBytesPerSec && probe != nil {
		// Under the floor on real traffic — actively probe the (idle) link, where the
		// probe is uncontended and accurate. Showing BOTH numbers makes it clear the
		// verdict isn't "idle link punished": an idle link is only degraded when the
		// probe ALSO comes up short.
		if pr, err := probe(ctx); err != nil {
			detail += ", probe failed: " + err.Error()
		} else {
			detail += fmt.Sprintf(", probe %s", kbPerSec(pr))
			if pr > rate {
				rate = pr
			}
		}
	}
	if rate < 0 {
		rate = 0
	}
	w.lastRate = rate
	healthy := rate >= w.MinBytesPerSec

	measured := detail + fmt.Sprintf(" (min %s)", kbPerSec(w.MinBytesPerSec))

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

	detail = measured
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

// kbPerSec formats a bytes/sec rate as a human KiB/s string (the floor is
// kbytes×1024, so the display unit is binary KiB to match exactly).
func kbPerSec(bps float64) string {
	return fmt.Sprintf("%.0f KiB/s", bps/1024)
}
