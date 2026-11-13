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
	// v8: MasterSpec.client_wg — the client-facing AmneziaWG interface, owned by the
	// agent. When it was introduced the hazard was the sharpest yet: the controller
	// treats the credentials in its own store as the truth, while a v7 agent (which
	// still ran wg-easy) drops the field, keeps that container running, and serves
	// whatever it last knew. Two sources of truth for the one leg end users
	// actually dial, with no error on either side. Deploy the controller FIRST;
	// a nil client_wg is the safe state — the controller renders no
	// client configs for that master.
	// v9 adds ClientWGSpec.ipv6_prefix. A v8 agent drops it and brings the client
	// interface up IPv4-only — while the controller, if it were not gated, would
	// already be writing "::/0" into every client config. The client would then
	// abandon its own working IPv6 path for one that silently drops, which is
	// the IPv6 black hole restaged: stalls that read as an MTU fault for days. Hence
	// WireClientIPv6 below, and hence the two must be rendered together or not at all.
	// v10 adds RenewCertificate. An agent below it has no way to renew and will run
	// to expiry in silence, so the gate is what tells the operator which nodes still
	// need a hand rather than letting them discover it one anniversary at a time.
	// v11 adds NodeSpec.lifeline and FirewallSpec.lifeline_port — an exit's reserve
	// client-facing AmneziaWG interface (product.md boundary 3: the fleet survives
	// the master itself being blocked or unreachable). A v10 agent drops both
	// fields: it neither brings the lifeline interface up nor opens its port, so an
	// exit designated to hold one silently carries none, and the fleet loses the
	// exact fallback it was configured to have precisely when the master is
	// unreachable — the one moment nobody is there to notice. Deploy the controller
	// FIRST.
	// v12 adds ExitTunnel.master_addr and StatusReport.awg_master_endpoint — the
	// exit-initiated AWG flow. A v11 master drops master_addr and keeps opening the
	// flow itself; a v11 exit applies an endpoint only on a config rewrite and
	// never reports it, so the controller would never arm the master's gate. Both
	// ends must be v12 before the controller turns the feature on for a tunnel.
	// v13 adds StatusReport.master_peers — an exit's per-master-peer endpoint and
	// handshake — and with it an exit agent that edits its master peers in place
	// instead of restarting the interface. Both matter only once a second master
	// exists: a v12 exit would restart awg0 for the new peer and could report one
	// endpoint for two masters, so the controller renders such an exit nothing but
	// the base master, exactly as before. Deploy the controller FIRST.
	// v14 adds RealityServerSpec.bridge, RealityTunnel.reverse and
	// MasterSpec.reality_portal — the exit-initiated REALITY mode. A v13 exit drops
	// the bridge and opens no flow to any master; a v13 master drops the portal and
	// keeps dialling an exit whose inbound is gone. Deploy the controller FIRST.
	// v16 adds NodeSpec.camouflage and StatusReport.camouflage_domain (ADR-0039,
	// own-domain camouflage). A v15 agent would drop the spec and never report the
	// domain; the controller gives such a node no camouflage and its peers keep the
	// fleet-default SNI, exactly as before.
	WireContractVersion uint32 = 16

	// WireClientWG is the wire version that introduced MasterSpec.client_wg. The
	// controller refuses to render the client interface for a master below it: such
	// an agent (one that still ran wg-easy) drops the field and keeps serving
	// whatever its own container last knew, while the controller treats its own
	// store as the truth. Two owners of the one leg end users dial, with no error
	// on either side. Named rather than
	// compared against WireContractVersion so a later bump for something unrelated
	// does not silently re-close the client interface to the whole fleet.
	WireClientWG uint32 = 8

	// WireCertRenewal is the wire version that introduced RenewCertificate. Below it
	// an agent cannot renew its own control-plane certificate: it will keep working
	// until NotAfter and then be refused, one node per provisioning anniversary. The
	// controller cannot fix that remotely — renewal needs a channel the expiry has
	// already closed — so the gate exists to make the set of such nodes visible while
	// something can still be done about it.
	WireCertRenewal uint32 = 10

	// WireClientIPv6 is the wire version that introduced ClientWGSpec.ipv6_prefix.
	// The controller refuses to hand clients an IPv6 default route unless the master's
	// agent can address the interface in v6 and answer forwarded v6 with an ICMPv6
	// rejection — without both halves "::/0" is a black hole, not a block. Named
	// rather than compared against WireContractVersion so a later bump for something
	// unrelated does not silently re-close this to the whole fleet.
	WireClientIPv6 uint32 = 9

	// WireLifeline is the wire version that introduced NodeSpec.lifeline and
	// FirewallSpec.lifeline_port. The controller refuses to render a lifeline for
	// an exit below it: such an agent drops both fields and brings up no reserve
	// client-facing interface at all, so the exit silently carries none of the
	// fallback capacity the operator configured — exactly the moment the fleet
	// needs it, since the lifeline exists for when the master is unreachable. Named
	// rather than compared against WireContractVersion so a later bump for
	// something unrelated does not silently re-close the lifeline to the whole
	// fleet.
	WireLifeline uint32 = 11

	// WireAWG3 is the wire version that introduced the AmneziaWG 3.0 block on
	// AWGShared. The controller refuses to render 3.0 params for a node below it:
	// such an agent drops the fields and brings its interface up as 2.0 while the
	// master's mihomo emits `version: 3`, and the two ends never handshake. Named
	// rather than compared against WireContractVersion so a later bump for an
	// unrelated feature does not silently re-close AWG 3.0 to the whole fleet.
	WireAWG3 uint32 = 7

	// WireAWGExitInitiated is the wire version that introduced the exit-initiated
	// AWG flow (ExitTunnel.master_addr, StatusReport.awg_master_endpoint). The
	// controller gives an exit the master's pinned endpoint only when the master
	// and the exit are both at or above it. Named rather than compared against
	// WireContractVersion so a later bump does not re-close it to the fleet.
	WireAWGExitInitiated uint32 = 12

	// WireMasterPeers is the wire version from which an exit can carry more than
	// the base master: it reports every master peer (StatusReport.master_peers)
	// and adds or removes one without restarting awg0. The controller renders a
	// non-base master's peer, route and tunnel only for an exit at or above it.
	// Named rather than compared against WireContractVersion so a later bump does
	// not re-close it.
	WireMasterPeers uint32 = 13

	// WireRealityReverse is the wire version that introduced the exit-initiated
	// REALITY mode (RealityServerSpec.bridge, RealityTunnel.reverse,
	// MasterSpec.reality_portal). The controller puts an exit in the mode only
	// when it is at or above it, and gives a master a reverse tunnel only when that
	// master is too. Named rather than compared against WireContractVersion so a
	// later bump does not re-close it.
	WireRealityReverse uint32 = 14

	// WireAWG3TrackB is the wire version that carries AWGShared.random_trailers.
	// Header protection now comes with trailers, equal S1-S4 and H1-H4 = 1-4
	// (AmneziaWG 3.1 "Track B"), and an agent below it would drop the trailers
	// flag and bring its end up without them while the other end — or the
	// device configs the controller renders — sends them. So every AmneziaWG 3.x
	// decision gates on this rather than on WireAWG3.
	WireAWG3TrackB uint32 = 15

	// WireCamouflage is the wire version that carries NodeSpec.camouflage and
	// StatusReport.camouflage_domain (ADR-0039). The controller sends camouflage
	// only to a node at or above it.
	WireCamouflage uint32 = 16

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
