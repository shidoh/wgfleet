package health

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// runner runs a command and returns its combined output; runCmd in production.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// PortalMasters maps each portal address of a bridge to its master's name.
func PortalMasters(bridge *domain.RealityBridgeSpec) map[netip.AddrPort]string {
	out := map[netip.AddrPort]string{}
	if bridge == nil {
		return out
	}
	for _, p := range bridge.Portals {
		if a, err := netip.ParseAddrPort(p.Address); err == nil {
			out[a] = p.Master
		}
	}
	return out
}

// SSSocket is one established TCP socket as `ss -tn[i]H state established`
// prints it. BytesReceived is filled only with -i, and is 0 until a byte arrives.
type SSSocket struct {
	Local, Peer   netip.AddrPort
	BytesReceived uint64
}

// ParseSSEstablished reads `ss -tnH state established` output, with or without
// -i: with a state filter ss drops the State column, so the local address is the
// third field and the peer the fourth; an -i info line follows its socket and is
// read for bytes_received. Addresses are unmapped from IPv4-in-IPv6.
func ParseSSEstablished(out string) []SSSocket {
	var socks []SSSocket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			local, lerr := netip.ParseAddrPort(f[2])
			peer, perr := netip.ParseAddrPort(f[3])
			if lerr == nil && perr == nil {
				socks = append(socks, SSSocket{
					Local: netip.AddrPortFrom(local.Addr().Unmap(), local.Port()),
					Peer:  netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()),
				})
				continue
			}
		}
		if len(socks) == 0 {
			continue
		}
		for _, field := range f {
			if v, found := strings.CutPrefix(field, "bytes_received:"); found {
				if n, err := strconv.ParseUint(v, 10, 64); err == nil {
					socks[len(socks)-1].BytesReceived = n
				}
			}
		}
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
	for _, p := range bridge.Portals {
		counts[p.Master] = 0
	}
	byAddr := PortalMasters(bridge)
	for _, s := range ParseSSEstablished(out) {
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
