package keybroker

import (
	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/domain"
)

// awg3Enabled decides whether one master↔exit tunnel is rendered with the
// AmneziaWG 3.0 block. It takes the operator's resolved intent (fleet.awg3 /
// exits[].awg3) and the registered node record of EVERY end of that tunnel, and
// all of them must agree.
//
// The wire gate is the load-bearing half. AmneziaWG 3.0 params are additive on the
// proto but not in behaviour: an agent below wire v7 silently DROPS them and
// renders a 2.0 tunnel end, while the other end — rendered by this same controller
// from this same decision — emits `version: 3`. The two ends then disagree about
// the wire format, no handshake completes, and the exit falls out of the load
// balancer. Refusing to render 3.0 degrades the premature flip to "this tunnel
// stays on 2.0", which is recoverable and visible, instead of to a dead tunnel.
//
// Passing EVERY end is the whole point, and for a long time this took only the
// exit's record while the comment beside both call sites claimed the two ends were
// "decided from the same inputs, so they cannot disagree". They were — and those
// inputs described one end. The master's own agent is what renders the mihomo side
// of the tunnel, and rollout.BuildPlan excludes masters from a rolling upgrade BY
// CONSTRUCTION (it walks fleet.Exits and never fleet.Masters), so a master lagging
// its exits is the fleet's ordinary state. Enabling fleet.awg3 in that state put
// every exit on 3.x and left the master's mihomo on 2.0: the entire data plane.
//
// Since header protection brings Track B with it (wg.WithAWG3HeaderProtection),
// the bar is WireAWG3TrackB, the version that carries random_trailers: an agent
// at WireAWG3 would take the key and drop the trailers.
//
// A node that has never reported a wire version (0 — never registered, or a build
// too old to send the metadata) is treated as too old, which is the same fail-safe
// direction api.CheckWire takes.
//
// This is the CONTROLLER's half of the gate and covers only what the controller
// can see. The exit's kernel-module generation is checked by the agent itself, on
// the node, every pass: 3.0 params on a 1.x module are rejected by awg setconf and
// the interface never comes up, and only the node knows which module it has.
func awg3Enabled(optIn bool, ends ...domain.Node) bool {
	if !optIn {
		return false
	}
	for _, n := range ends {
		if n.WireVersion < api.WireAWG3TrackB {
			return false
		}
	}
	return len(ends) > 0
}
