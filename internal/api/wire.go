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
	// v5: additive FirewallSpec.public_udp_ports (world-facing UDP accepts). A v4
	// agent silently drops the field and renders a ruleset WITHOUT the accept, so
	// the operator's configured UDP port stays closed with no error — the same
	// "configured port stays closed" convergence hazard as v3, hence the bump.
	// Motivating case: a ZeroTier controller co-located with the node's own member
	// instance, which must listen on a non-default port.
	// v6: NodeSpec.hardening (fleet.hardening — the operator's opt-out from the
	// managed sshd drop-in and fail2ban jail). This one bumps for the OPPOSITE
	// reason to v3/v5: the hazard is not a closed port but an ignored opt-out. A v5
	// agent drops the field, reads "unset", and goes on hardening the node — the
	// planner rewrites the drop-in and reloads sshd every pass, silently reverting
	// an operator who explicitly turned it off. That is a convergence difference the
	// agent must understand, so the safe default ("unset ⇒ hardened") does NOT make
	// the change additive. Deploy the controller FIRST.
	// v7: AWGShared gains the AmneziaWG 3.0 block (header_protection_key,
	// content_padding_addition and the five u16-range timers). The hazard here is a
	// SPLIT TUNNEL rather than a missing feature: a v6 exit agent drops the fields
	// and brings awg0 up as a 2.0 interface, while the master's mihomo — rendered by
	// the same controller from the same decision — emits `version: 3`. The two ends
	// then disagree about the wire format and no handshake completes, so the exit
	// drops out of the load balancer. Additive on the proto, decidedly not additive
	// in behaviour, hence the bump; and because a bump alone would still let a
	// not-yet-rolled agent hit exactly that split, the controller ALSO refuses to
	// render 3.0 params for a node reporting less than v7 (keybroker.awg3For).
	// Deploy the controller FIRST.
	// v8: MasterSpec.client_wg — the client-facing AmneziaWG interface once the
	// agent, rather than wg-easy, owns it. The hazard is the sharpest yet: the
	// controller flips fleet.masters[].client_awg.managed, stops reconciling the
	// wg-easy database and starts treating the credentials in its own store as the
	// truth, while a v7 agent drops the field, keeps wg-easy running, and serves
	// whatever that container last knew. Two sources of truth for the one leg end
	// users actually dial, with no error on either side. Deploy the controller
	// FIRST, and note that a nil client_wg is the safe state: it means
	// "wg-easy still owns this leg", which is what every un-migrated master reports.
	WireContractVersion uint32 = 8

	// WireClientWG is the wire version that introduced MasterSpec.client_wg. The
	// controller refuses to render the client interface for a master below it: such
	// an agent drops the field, keeps wg-easy running and keeps serving whatever
	// that container last knew, while the controller has already stopped reconciling
	// wg-easy's database and treats its own store as the truth. Two owners of the
	// one leg end users dial, with no error on either side. Named rather than
	// compared against WireContractVersion so a later bump for something unrelated
	// does not silently re-close the client interface to the whole fleet.
	WireClientWG uint32 = 8

	// WireAWG3 is the wire version that introduced the AmneziaWG 3.0 block on
	// AWGShared. The controller refuses to render 3.0 params for a node below it:
	// such an agent drops the fields and brings its interface up as 2.0 while the
	// master's mihomo emits `version: 3`, and the two ends never handshake. Named
	// rather than compared against WireContractVersion so a later bump for an
	// unrelated feature does not silently re-close AWG 3.0 to the whole fleet.
	WireAWG3 uint32 = 7

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
