package keybroker

import (
	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/domain"
)

// awg3Enabled decides whether one exit's master↔exit tunnel is rendered with the
// AmneziaWG 3.0 block. It takes the operator's resolved intent (fleet.awg3 /
// exits[].awg3) and the exit's registered node record, and both must agree.
//
// The wire gate is the load-bearing half. AmneziaWG 3.0 params are additive on the
// proto but not in behaviour: an agent below wire v7 silently DROPS them and
// brings awg0 up as a 2.0 interface, while the master's mihomo — rendered by this
// same controller from this same decision — would emit `version: 3`. The two ends
// then disagree about the wire format, no handshake completes, and the exit falls
// out of the load balancer. Refusing to render 3.0 for such a node degrades the
// premature flip to "this exit stays on 2.0", which is recoverable and visible,
// instead of to a dead tunnel.
//
// A node that has never reported a wire version (0 — never registered, or a build
// too old to send the metadata) is treated as too old, which is the same fail-safe
// direction api.CheckWire takes.
//
// This is the CONTROLLER's half of the gate and covers only what the controller
// can see. The exit's kernel-module generation is checked by the agent itself, on
// the node, every pass: 3.0 params on a 1.x module are rejected by awg setconf and
// the interface never comes up, and only the node knows which module it has.
func awg3Enabled(optIn bool, node domain.Node) bool {
	return optIn && node.WireVersion >= api.WireAWG3
}
