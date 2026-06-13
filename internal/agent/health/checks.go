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
}

// MasterProbes are the injectable probes for a master node's self-checks.
type MasterProbes struct {
	MihomoAPI  Probe // mihomo Clash API responds
	WGServerUp Probe // client-facing WG/AWG interface is up
}

// ExitChecks builds an exit node's check set from spec + probes. Checks that are
// not relevant to the spec (e.g. WARP egress when egress is direct) are omitted.
func ExitChecks(spec domain.NodeSpec, p ExitProbes) []Check {
	var checks []Check
	if p.HandshakeFresh != nil {
		checks = append(checks, Check{Name: "wg-handshake", Probe: p.HandshakeFresh})
	}
	if spec.Egress == domain.EgressWARP && p.WARPEgress != nil {
		checks = append(checks, Check{Name: "warp-egress", Probe: p.WARPEgress})
	}
	if spec.DNS.Enabled && p.DNSResolves != nil {
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
	return checks
}
