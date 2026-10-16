package health

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// runner runs a command and returns its combined output; runCmd in production.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// ssSocket is one line of `ss -tnH state established`.
type ssSocket struct {
	Local, Peer netip.AddrPort
}

// parseSSEstablished reads `ss -tnH state established` output: with a state
// filter ss drops the State column, so the local address is the third field and
// the peer the fourth. Lines that do not parse (info lines of `ss -i`) are skipped.
func parseSSEstablished(out string) []ssSocket {
	var socks []ssSocket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local, lerr := netip.ParseAddrPort(f[2])
		peer, perr := netip.ParseAddrPort(f[3])
		if lerr != nil || perr != nil {
			continue
		}
		socks = append(socks, ssSocket{
			Local: netip.AddrPortFrom(local.Addr().Unmap(), local.Port()),
			Peer:  netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()),
		})
	}
	return socks
}

// BridgeConnections counts the bridge's established connections to each portal,
// keyed by master name, from `ss -tnH state established` output. Every portal of
// the spec is present, a disconnected one with zero.
func BridgeConnections(out string, bridge *domain.RealityBridgeSpec) map[string]int {
	counts := map[string]int{}
	if bridge == nil {
		return counts
	}
	byAddr := map[netip.AddrPort]string{}
	for _, p := range bridge.Portals {
		counts[p.Master] = 0
		if a, err := netip.ParseAddrPort(p.Address); err == nil {
			byAddr[a] = p.Master
		}
	}
	for _, s := range parseSSEstablished(out) {
		if m, ok := byAddr[s.Peer]; ok {
			counts[m]++
		}
	}
	return counts
}

// bridgeProbe checks the exit's reverse bridge (ADR-0038) holds an established
// connection to at least one master's portal. One master down is not the exit's
// fault and must not mark it Degraded; per-master state is a metric.
func bridgeProbe(bridge *domain.RealityBridgeSpec, run runner) Probe {
	return func(ctx context.Context) Result {
		if bridge == nil || len(bridge.Portals) == 0 {
			return fail("no portal to dial")
		}
		start := now()
		out, err := run(ctx, "ss", "-tnH", "state", "established")
		if err != nil {
			return fail(fmt.Sprintf("ss failed: %v", err))
		}
		counts := BridgeConnections(out, bridge)
		var up []string
		for _, p := range bridge.Portals {
			if counts[p.Master] > 0 {
				up = append(up, p.Master)
			}
		}
		if len(up) == 0 {
			return fail(fmt.Sprintf("no established connection to any of %d portal(s)", len(bridge.Portals)))
		}
		return ok(fmt.Sprintf("connected to %d/%d portal(s): %s", len(up), len(bridge.Portals), strings.Join(up, ",")), since(start))
	}
}
