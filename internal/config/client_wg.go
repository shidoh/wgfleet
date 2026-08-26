package config

import (
	"fmt"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Validation for the client-facing AmneziaWG interface. It lives beside the
// credential subsystem it serves rather than in the controller.go wall of
// checks, because these rules are about one subject: who owns the client leg and
// on what addresses.

// validateClientAWG checks one master's client_awg block.
func validateClientAWG(i int, m MasterConfig) []error {
	var errs []error

	switch m.ClientAWGBackend() {
	case domain.ClientWGBackendKernel, domain.ClientWGBackendUserspace:
	default:
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: unknown client_awg.backend %q (want kernel or userspace)",
			i, m.ClientAWG.Backend))
	}

	// The pool is optional while wg-easy owns the interface (it keeps its own
	// state), but a managed interface is rendered FROM the pool: addresses are
	// allocated out of it and the master's own address sits inside it.
	if m.ClientAWGManaged() && m.ClientAWG.AddressPool == "" {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.address_pool is required when client_awg.managed is true", i))
	}

	if mtu := m.ClientAWG.MTU; mtu != 0 && (mtu < minClientAWGMTU || mtu > maxClientAWGMTU) {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.mtu %d out of range (0 to derive, else %d..%d)",
			i, mtu, minClientAWGMTU, maxClientAWGMTU))
	}

	for _, a := range m.ClientAWGAllowedIPs() {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.allowed_ips entry %q is not a valid CIDR: %w", i, a, err))
			continue
		}
		// The data plane is IPv4-only. wg-easy's own default put "::/0" in front of
		// every client and stalled dual-stack traffic until the operator re-imported
		// every device; owning the render means refusing to repeat it.
		if p.Addr().Is6() && p.Bits() == 0 {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.allowed_ips must not contain the IPv6 default route %q on an IPv4-only data plane", i, a))
		}
	}

	for _, d := range m.ClientAWGDNS() {
		if _, err := netip.ParseAddr(d); err != nil {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.dns entry %q is not an IP address: %w", i, d, err))
		}
	}
	return errs
}

// validateClientPoolsDisjoint rejects masters whose client pools overlap. With
// one master this is trivially satisfied; it exists for the multi-master fleet
// (ADR-0027), where an address that belongs to two gateways is ambiguous the
// moment traffic crosses between them — and where the mistake would surface as
// intermittent, hard-to-attribute breakage rather than as a startup error.
func validateClientPoolsDisjoint(masters []MasterConfig) []error {
	type pool struct {
		name   string
		prefix netip.Prefix
	}
	var (
		seen []pool
		errs []error
	)
	for _, m := range masters {
		if m.ClientAWG.AddressPool == "" {
			continue
		}
		p, err := netip.ParsePrefix(m.ClientAWG.AddressPool)
		if err != nil {
			continue // already reported as a malformed CIDR
		}
		p = p.Masked()
		for _, other := range seen {
			if p.Overlaps(other.prefix) {
				errs = append(errs, fmt.Errorf("fleet.masters: client_awg.address_pool %s of %q overlaps %s of %q",
					p, m.Name, other.prefix, other.name))
			}
		}
		seen = append(seen, pool{name: m.Name, prefix: p})
	}
	return errs
}

// minClientAWGMTU / maxClientAWGMTU bound the operator's MTU override: below the
// IPv6 minimum nothing carries reliably, above a real Ethernet path the value is
// meaningless.
const (
	minClientAWGMTU = 1280
	maxClientAWGMTU = 1500
)
