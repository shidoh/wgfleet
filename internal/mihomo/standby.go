package mihomo

import "github.com/shidoh/wgfleet/internal/domain"

// StandbyTunnel is one exit's INACTIVE transport: a proxy the master renders and
// keeps configured, but deliberately keeps out of the load-balance group so no
// new traffic routes to it (ADR-0025). It is what an operator switches TO.
type StandbyTunnel struct {
	Proxy     string                 // mihomo proxy name — what a Clash probe addresses
	Exit      string                 // exit node name — what an operator and a metric label
	Transport domain.MasterTransport // the transport this standby carries
}

// StandbyTransports lists the standby transports in the spec.
//
// It exists because "drained" answers WHAT (keep this proxy out of the group)
// without answering WHY, and the two reasons want opposite treatment:
//
//   - the operator drained the exit, or the throughput watchdog auto-suspended
//     it — the node is deliberately out of service and must not be dialled;
//   - it is the standby half of a dual-transport exit — the node is in service,
//     and this is the path we would move it to in an emergency.
//
// The controller ORs the first reason into BOTH of an exit's tunnels and the
// second into exactly one (keybroker: `baseDrained || realityActive` and
// `baseDrained || !realityActive`). So a drained tunnel WITH A LIVE SIBLING is a
// standby transport, and a drained tunnel whose siblings are all drained is a
// drained exit. That is the whole discriminator, and it needs no new wire field
// precisely because the existing flags already carry the distinction.
//
// Why anyone wants this list: a standby transport is in no tier, so neither the
// tier decision nor the standby-TIER warm probe ever dials it, and its mihomo
// health readings therefore never update. Without it, no standby transport is
// ever health-checked: most report alive=1, which is mihomo's default for an
// untested proxy rather than evidence, and the rest stay frozen on a verdict
// nobody rechecks. ADR-0025's plan promised "per-transport
// reachability"; the active-transport metric shipped and this half did not.
//
// Order follows the spec so the probe load lands in a stable sequence.
func StandbyTransports(spec domain.MasterSpec) []StandbyTunnel {
	live := make(map[string]bool, len(spec.ExitTunnels))
	for _, t := range spec.ExitTunnels {
		if !t.Drained {
			live[t.ExitNode()] = true
		}
	}
	var out []StandbyTunnel
	for _, t := range spec.ExitTunnels {
		exit := t.ExitNode()
		if !t.Drained || !live[exit] {
			continue
		}
		out = append(out, StandbyTunnel{
			Proxy:     t.Name,
			Exit:      exit,
			Transport: t.Transport.OrDefault(),
		})
	}
	return out
}

// StandbyProxies is StandbyTransports reduced to the proxy names a prober needs.
func StandbyProxies(spec domain.MasterSpec) []string {
	st := StandbyTransports(spec)
	out := make([]string, 0, len(st))
	for _, t := range st {
		out = append(out, t.Proxy)
	}
	return out
}
