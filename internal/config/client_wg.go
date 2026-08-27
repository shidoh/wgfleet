package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

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

	// The 3.x mode. Rejecting an unknown value matters more here than for most
	// knobs: the neighbouring fleet.awg3 is a BOOL, so "awg3: true" is exactly what
	// an operator writes from memory — and silently resolving it to off would leave
	// them believing their clients run 3.x while every packet stays 2.0.
	switch mode := strings.ToLower(strings.TrimSpace(m.ClientAWG.AWG3)); mode {
	case "", string(ClientAWG3Off), string(ClientAWG3Timers), string(ClientAWG3Full):
	default:
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: unknown client_awg.awg3 %q "+
			"(want off, timers or full; \"timers\" keeps every existing client config working, "+
			"\"full\" adds header protection and requires all of them to be re-imported)", i, m.ClientAWG.AWG3))
	}
	// wg-easy's schema has no column for any 3.0 parameter, so while it owns the
	// leg the knob has nowhere to land. Refusing beats writing 2.0 to the wire
	// under a manifest that says 3.x.
	if m.ClientAWG3() != ClientAWG3Off && !m.ClientAWGManaged() {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.awg3 is %q but client_awg.managed is not true — "+
			"while wg-easy owns the client leg it cannot carry AmneziaWG 3.x, and the setting would silently do nothing",
			i, m.ClientAWG.AWG3))
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

	if err := domain.ValidateClientKeepalive(m.ClientAWG.Keepalive); err != nil {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.%w", i, err))
	}

	// The expansion is arithmetic on operator input, so a typo must fail at startup
	// rather than silently produce a routing table nobody intended.
	if _, err := domain.ExpandAllowedIPs(m.ClientAWG.ExcludeFromTunnel, m.ClientAWG.RouteThroughCIDRs); err != nil {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.%w", i, err))
	}
	if len(m.ClientAWG.RouteThroughCIDRs) > 0 && len(m.ClientAWG.ExcludeFromTunnel) == 0 {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.route_through_cidrs is set but "+
			"client_awg.exclude_from_tunnel is not — nothing has been taken out of the tunnel, so there is "+
			"nothing to put back and the setting does nothing", i))
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

// validateClientPortal checks the client self-service portal's two knobs. They
// are one deployment decision: a bind nobody can reach is useless, and a bind
// with no published URL is a portal the operator has no link for — which is how
// the whole surface ends up unreachable while looking configured.
func validateClientPortal(bind, base string) []error {
	var errs []error
	if bind == "" {
		if base != "" {
			errs = append(errs, fmt.Errorf("controller.client_portal_url is set but controller.client_portal is not — nothing is listening at that URL"))
		}
		return errs
	}
	if err := requireListenAddr("controller.client_portal", bind); err != nil {
		errs = append(errs, err)
	}
	if base == "" {
		errs = append(errs, fmt.Errorf("controller.client_portal is bound but controller.client_portal_url is unset — "+
			"the controller cannot derive the address clients type, so the Web UI has no link to hand out"))
		return errs
	}
	u, err := url.Parse(base)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("controller.client_portal_url %q is not a URL: %w", base, err))
	case u.Scheme != "http" && u.Scheme != "https":
		errs = append(errs, fmt.Errorf("controller.client_portal_url %q must start with http:// or https://", base))
	case u.Host == "":
		errs = append(errs, fmt.Errorf("controller.client_portal_url %q has no host", base))
	case u.Scheme == "http" && !localHost(u.Hostname()):
		// The portal serves WireGuard private keys. Plaintext is acceptable when the
		// hop rides inside the client tunnel or a local proxy; to a routable host it
		// is a key handed to whoever is on the path.
		errs = append(errs, fmt.Errorf("controller.client_portal_url %q serves private keys over plain http to a routable host — "+
			"use https, or publish the address clients reach through the tunnel", base))
	}
	return errs
}

// localHost reports whether a host is one the portal may serve plaintext to:
// a loopback, RFC1918/ULA or link-local ADDRESS.
//
// A DNS name is deliberately NOT local here, unlike elsewhere in this file where
// an unresolvable name is left to the operator's judgement. The asymmetry is the
// point: this URL is handed to end users and returns a WireGuard private key, and
// a name implies public DNS far more often than it implies a tunnel-local host.
// An operator terminating TLS locally writes https, or 127.0.0.1.
func localHost(host string) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}
