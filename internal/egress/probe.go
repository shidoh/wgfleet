package egress

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/shidoh/wgfleet/internal/wg"
)

// pmtuRe captures the path-MTU value tracepath prints on each hop and the final
// "resume: pmtu N" line. We take the LAST match — the converged path MTU.
var pmtuRe = regexp.MustCompile(`pmtu\s+(\d+)`)

// ProbeWARPMTU measures the path MTU to the WARP endpoint host and returns the
// wgcf interface MTU that fits it (path MTU minus the plain-WG IPv4 overhead),
// clamped to [MinTunnelMTU, DefaultWARPMTU]. It shells out to `tracepath` (Apply-
// side only — it sends probe packets, so it must never run in Plan/dry-run).
//
// Safety by construction: the result is capped at wg.DefaultWARPMTU, so the probe
// can only LOWER the MTU for a genuinely constrained path, never RAISE it above the
// conservative default. tracepath sees the OUTER path to the endpoint IP (often a
// full 1500); Cloudflare's inner WARP MTU is smaller and not directly measurable
// here, so raising toward the outer path would re-introduce the egress black-hole
// this whole mechanism exists to avoid. An operator who needs a higher value sets
// warp_mtu explicitly (which bypasses the probe). Any error ⇒ caller keeps the default.
func ProbeWARPMTU(ctx context.Context, endpoint string) (int, error) {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	// tracepath probes the path itself; -n skips reverse-DNS for speed.
	//
	// -4 is NOT optional. The WARP endpoint host resolves AAAA-first on a dual-stack
	// resolver (2606:4700:d0::a29f:c001), and the fleet's data plane is IPv4-only:
	// an unforced tracepath then probes a v6 path that black-holes, burns the caller's
	// whole timeout, and dies with "signal: killed" on EVERY node — auto-MTU discovery
	// silently dead fleet-wide while the default masked it. Pinning v4 probes the same
	// 162.159.192.1 the wgcf peer endpoint actually uses, which is the path we mean to
	// measure. (iputils tracepath has supported -4 for well over a decade.)
	args := tracepathArgs(host)
	out, err := exec.CommandContext(ctx, "tracepath", args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return 0, fmt.Errorf("tracepath -4 %s: %w", host, err)
	}
	pmtu := lastPMTU(string(out))
	if pmtu <= 0 {
		return 0, fmt.Errorf("tracepath %s: no pmtu in output", host)
	}
	mtu := pmtu - wg.WGOverheadIPv4
	if mtu < wg.MinTunnelMTU {
		mtu = wg.MinTunnelMTU
	}
	if mtu > wg.DefaultWARPMTU {
		mtu = wg.DefaultWARPMTU
	}
	return mtu, nil
}

// maxProbeHops caps tracepath's TTL walk.
//
// tracepath decides it has ARRIVED when the destination answers ICMP
// port-unreachable. Cloudflare's anycast edge never does — and stops answering
// altogether a few hops in — so an uncapped run has no stop condition and walks its
// full 30-hop default at roughly a second per silent hop. That overruns the 30s
// deadline the caller gives the probe, and the resulting SIGKILL discards
// tracepath's block-buffered stdout, so ProbeWARPMTU's `len(out) == 0` salvage path
// never sees the partial output it was written for. Net effect before this cap:
// every exit in the fleet logged "signal: killed" and auto-MTU discovery was dead,
// silently, with the conservative default masking it.
//
// Nothing is lost by stopping early: the hops beyond the cap are the silent ones,
// and the pmtu that matters is reported by the near hops (the constrained link is
// the first one, e.g. a provider gateway advertising 1456). A path that narrows
// beyond the cap is still safe — ProbeWARPMTU clamps to wg.DefaultWARPMTU, so a
// missed constraint leaves the conservative default rather than raising the MTU.
//
// Measured 2026-08-04 on vn0/anz3/pn80: capped, tracepath exits 0 in 9-16s and
// prints "Resume: pmtu N", which is what lastPMTU parses.
const maxProbeHops = 10

// tracepathArgs builds the tracepath invocation for host. Split out from the exec
// call so the -4 pin and the hop cap are covered by tests rather than only by
// comments.
func tracepathArgs(host string) []string {
	return []string{"-4", "-n", "-m", strconv.Itoa(maxProbeHops), host}
}

// lastPMTU returns the last pmtu value in tracepath output, or 0 if none.
func lastPMTU(out string) int {
	m := pmtuRe.FindAllStringSubmatch(out, -1)
	if len(m) == 0 {
		return 0
	}
	n, err := strconv.Atoi(m[len(m)-1][1])
	if err != nil {
		return 0
	}
	return n
}
