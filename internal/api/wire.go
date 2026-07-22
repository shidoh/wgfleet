package api

import "fmt"

// Wire-contract versioning governs controller↔agent compatibility independently
// of the build (git) version. The proto messages are forward/backward tolerant
// at the bytes level (proto3 silently ignores unknown fields), which is exactly
// the hazard: a too-old agent would drop a new spec field (e.g. egress_chain,
// decommission) and SILENTLY half-apply. The wire version turns that silent skew
// into an explicit, fail-safe gate. See docs/upgrade.md and docs/adr/0019.
//
// Bump rules:
//   - WireContractVersion: increment on ANY change agents must understand to
//     converge correctly (new NodeSpec semantics, changed field meaning).
//   - MinSupportedWire: raise only when dropping support for old agents; this is
//     a deliberate, breaking, documented step (it strands un-upgraded agents on
//     their last-good spec until they are re-rolled).
const (
	// WireContractVersion is the protocol version this build speaks.
	// v2: additive StatusReport.exit_health (master per-exit tunnel health). An
	// older agent simply omits it; an older controller ignores it.
	// v3: additive FirewallSpec.public_tcp_ports (world-facing TCP accepts). A v2
	// agent silently drops the field and renders a ruleset WITHOUT the accept, so
	// the operator's configured port stays closed with no error — a convergence
	// difference the agent must understand, hence the bump.
	// v4: MasterSpec.client_vless (client-facing VLESS+REALITY+XHTTP inbound). A v3
	// agent silently drops it and renders the master WITHOUT the client VLESS
	// listener the operator configured (and never publishes the master's REALITY
	// key), so the client transport stays down with no error — same "configured
	// port stays closed" convergence hazard as v3, hence the bump. Deploy the
	// controller FIRST: an agent newer than the controller is refused
	// entirely (WireAgentTooNew), while an older agent stays compatible.
	WireContractVersion uint32 = 4

	// MinSupportedWire is the oldest agent wire version the controller will serve
	// a spec to. Agents below it are refused (fail-safe) and, where possible,
	// auto-upgraded.
	MinSupportedWire uint32 = 1
)

// gRPC metadata keys the agent attaches to every RPC so the controller can gate
// before acting. Lower-case per gRPC metadata convention.
const (
	MDWireVersion  = "wgfleet-wire-version"
	MDAgentVersion = "wgfleet-agent-version"
)

// Compatibility classifies an agent's wire version against this controller.
type Compatibility int

const (
	// WireCompatible: the agent's wire version is within the served range.
	WireCompatible Compatibility = iota
	// WireAgentTooOld: agent below MinSupportedWire — auto-upgradable (push a new
	// agent binary), so reject-and-upgrade.
	WireAgentTooOld
	// WireAgentTooNew: agent above WireContractVersion — the CONTROLLER is behind
	// and must be upgraded first; the controller cannot render the newer contract,
	// so reject (auto-upgrade cannot fix a too-old controller).
	WireAgentTooNew
	// WireUnknown: the agent sent no/garbage wire version. Treated as too old
	// (a pre-versioning agent), so it is refused and rolled forward.
	WireUnknown
)

// CheckWire classifies an agent-reported wire version. ok reports whether the
// controller will serve the agent a spec.
func CheckWire(agentWire uint32) Compatibility {
	switch {
	case agentWire == 0:
		return WireUnknown
	case agentWire < MinSupportedWire:
		return WireAgentTooOld
	case agentWire > WireContractVersion:
		return WireAgentTooNew
	default:
		return WireCompatible
	}
}

// String renders a compatibility verdict for logs and status detail.
func (c Compatibility) String() string {
	switch c {
	case WireCompatible:
		return "compatible"
	case WireAgentTooOld:
		return "agent-too-old"
	case WireAgentTooNew:
		return "agent-too-new"
	case WireUnknown:
		return "wire-version-unknown"
	default:
		return fmt.Sprintf("Compatibility(%d)", int(c))
	}
}

// AutoUpgradable reports whether pushing a fresh agent binary can resolve the
// incompatibility (true only when the agent is behind the controller).
func (c Compatibility) AutoUpgradable() bool {
	return c == WireAgentTooOld || c == WireUnknown
}

// IncompatibilityDetail builds a human-readable reason for the node's status.
func IncompatibilityDetail(c Compatibility, agentWire uint32) string {
	return fmt.Sprintf("agent wire v%d %s (controller serves v%d..v%d)",
		agentWire, c, MinSupportedWire, WireContractVersion)
}
