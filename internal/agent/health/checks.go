package health

import "github.com/shidoh/wgfleet/internal/domain"

// ExitProbes are the injectable probes for an exit node's self-checks. Tests
// supply stubs; production wires the real exec/http probes (probes.go).
type ExitProbes struct {
	HandshakeFresh Probe // freshest master↔exit WG handshake under threshold
	WARPEgress     Probe // egress leaves via Cloudflare WARP
	DNSResolves    Probe // on-node DNS filter resolves
	// EgressConfirm actively checks whether the WARP path itself is reachable (the
	// WG handshake to the Cloudflare endpoint is fresh). Run only when WARPEgress
	// has failed repeatedly, it distinguishes an ISP/DPI block from a transient
	// blip — see EgressClassifier. Non-destructive (read-only; never re-registers
	// wgcf, which would churn the node's WARP account — an earlier finding).
	EgressConfirm Probe
	// RealityInbound checks the xray REALITY inbound is listening (ADR-0025). Run
	// in place of the WG-handshake check when REALITY is the active transport.
	RealityInbound Probe
}

// MasterProbes are the injectable probes for a master node's self-checks.
type MasterProbes struct {
	MihomoAPI     Probe // mihomo Clash API responds
	WGServerUp    Probe // client-facing WG/AWG interface is up
	DNSResolves   Probe // master-tier blocky resolves (ADR-0024); nil when no resolver
	ClientVLESSUp Probe // client-facing VLESS/REALITY inbound is listening (ADR-0031); nil when not run
	// ClientWGOwned reports that the AGENT is carrying the client interface, not
	// merely that an interface of that name exists (wg-easy's does too). nil when
	// the agent does not manage the leg.
	ClientWGOwned Probe
	// ClientUDPReturn asserts that no UDP port this node holds silently black-holes
	// client traffic to it. nil when the agent does not manage the client leg —
	// the ports that collide are the ones WE put on the wire.
	ClientUDPReturn Probe
}

// ExitChecks builds an exit node's check set from spec + probes. Checks that are
// not relevant to the spec (e.g. WARP egress when egress is direct) are omitted.
func ExitChecks(spec domain.NodeSpec, p ExitProbes) []Check {
	var checks []Check
	// The active master↔exit transport determines which link must be healthy. When
	// REALITY is active the AWG server is a warm standby with no handshake, so the
	// wg-handshake check would always fail and falsely mark the node Degraded — check
	// the reality inbound instead (ADR-0025). AWG-active exits keep the WG check.
	if spec.HasTransport(domain.TransportRealityXHTTP) &&
		spec.ActiveTransport.OrDefault() == domain.TransportRealityXHTTP {
		if p.RealityInbound != nil {
			checks = append(checks, Check{Name: "reality-inbound", Probe: p.RealityInbound})
		}
	} else if p.HandshakeFresh != nil {
		checks = append(checks, Check{Name: "wg-handshake", Probe: p.HandshakeFresh})
	}
	if spec.Egress == domain.EgressWARP && p.WARPEgress != nil {
		checks = append(checks, Check{Name: "warp-egress", Probe: p.WARPEgress})
	}
	// Only check DNS once the resolver has a listen address. The dnsPlanner defers
	// (NoChangeAction) until the controller knows the node's mgmt addr; without
	// this guard the check fires "no DNS listen address" and falsely marks the node
	// Degraded during that startup window.
	if spec.DNS.Enabled && spec.DNS.MgmtAddr != "" && p.DNSResolves != nil {
		checks = append(checks, Check{Name: "dns-filter", Probe: p.DNSResolves})
	}
	return checks
}

// MasterChecks builds a master node's check set.
func MasterChecks(spec domain.NodeSpec, p MasterProbes) []Check {
	var checks []Check
	if p.WGServerUp != nil {
		checks = append(checks, Check{Name: "client-wg", Probe: p.WGServerUp})
	}
	if spec.Master != nil && spec.Master.ExternalController != "" && p.MihomoAPI != nil {
		checks = append(checks, Check{Name: "mihomo-api", Probe: p.MihomoAPI})
	}
	// Master-tier blocky (ADR-0024): the master is the clients' resolver, so a
	// blocky that is up-but-not-resolving (or down) must show Degraded, not Ready.
	// Guarded by the listen address like the exit check, so the node is not falsely
	// Degraded during the startup window before the resolver has a bind.
	if spec.DNS.Enabled && spec.DNS.MgmtAddr != "" && p.DNSResolves != nil {
		checks = append(checks, Check{Name: "dns-filter", Probe: p.DNSResolves})
	}
	// Client-facing VLESS/REALITY inbound (ADR-0031): when the master runs it
	// alongside client AWG, a down inbound must show Degraded — DPI-throttled clients
	// rely on it. Only checked when the master spec actually carries the inbound.
	if spec.Master != nil && spec.Master.ClientVLESS != nil && p.ClientVLESSUp != nil {
		checks = append(checks, Check{Name: "client-vless", Probe: p.ClientVLESSUp})
	}
	// When the agent owns the client leg, "an interface named wg0 exists" is not
	// enough: it is also true while wg-easy holds it, and it stays true through
	// every deferral the interface planner can report (no key yet, spec rejected,
	// AmneziaWG 3.x refused). Without this check those states leave the node Ready
	// and green with the client leg unmanaged — the operator's only signal would be
	// a line in a plan nobody is reading at 3am.
	if spec.Master != nil && spec.Master.ClientWG != nil && p.ClientWGOwned != nil {
		checks = append(checks, Check{Name: "client-wg-owned", Probe: p.ClientWGOwned})
	}
	// The client UDP return path. Deliberately NOT named `client-…`: the alert
	// WgfleetClientPathDown matches `check=~"client-wg.*|client-vless"` and is
	// critical for 5m, and a name that drifted into that regexp would turn a
	// port-inventory finding into a paging outage.
	if spec.Master != nil && spec.Master.ClientWG != nil && p.ClientUDPReturn != nil {
		checks = append(checks, Check{Name: "udp-return-path", Probe: p.ClientUDPReturn})
	}
	return checks
}
