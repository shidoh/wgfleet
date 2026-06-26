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
// clamped to [MinTunnelMTU, FleetTunnelMTU]. It shells out to `tracepath` (Apply-
// side only — it sends probe packets, so it must never run in Plan/dry-run). The
// caller treats any error as "keep the default": an unprobeable path falls back to
// wg.DefaultWARPMTU rather than guessing.
func ProbeWARPMTU(ctx context.Context, endpoint string) (int, error) {
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	// tracepath probes the path itself; -n skips reverse-DNS for speed.
	out, err := exec.CommandContext(ctx, "tracepath", "-n", host).CombinedOutput()
	if err != nil && len(out) == 0 {
		return 0, fmt.Errorf("tracepath %s: %w", host, err)
	}
	pmtu := lastPMTU(string(out))
	if pmtu <= 0 {
		return 0, fmt.Errorf("tracepath %s: no pmtu in output", host)
	}
	mtu := pmtu - wg.WGOverheadIPv4
	if mtu < wg.MinTunnelMTU {
		mtu = wg.MinTunnelMTU
	}
	if max := wg.FleetTunnelMTU(false, false); mtu > max {
		mtu = max
	}
	return mtu, nil
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
