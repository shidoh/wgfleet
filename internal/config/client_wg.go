package config

import (
	"fmt"
	"net"
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
func validateClientAWG(i int, m MasterConfig, fleet FleetSection) []error {
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
	// The pool must have a host #1 — the master's own address inside it. Without
	// one the broker's masterClientAddress fails, and that failure now aborts the
	// WHOLE spec render, so a plausible typo like "10.80.0.5/32" would stop this
	// master converging mihomo, the NAT, DOCKER-USER, blocky and the VLESS inbound
	// as well. Catch it here, where it costs a startup error instead.
	if pool := m.ClientAWG.AddressPool; pool != "" {
		if p, err := netip.ParsePrefix(pool); err == nil {
			if first := p.Masked().Addr().Next(); !first.IsValid() || !p.Contains(first) {
				errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.address_pool %s has no host address for the "+
					"master itself — it needs room for at least a gateway and one client (a /30 or wider)", i, pool))
			}
		}
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
	errs = append(errs, validateTunnelReachesItself(i, m, fleet)...)

	switch m.ClientAWG.IPv6 {
	case "", ClientIPv6Off, ClientIPv6Block:
	default:
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: unknown client_awg.ipv6 %q (want %q or %q)",
			i, m.ClientAWG.IPv6, ClientIPv6Off, ClientIPv6Block))
	}
	if m.ClientAWG.IPv6 == ClientIPv6Block && !m.ClientAWGManaged() {
		errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.ipv6 is %q but client_awg.managed is not true — "+
			"only the agent-owned interface can answer IPv6; wg-easy would hand out the route and drop the packets",
			i, ClientIPv6Block))
	}

	for _, a := range m.ClientAWGAllowedIPs() {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.allowed_ips entry %q is not a valid CIDR: %w", i, a, err))
			continue
		}
		// wg-easy's own default put "::/0" in front of every client over an IPv4-only
		// data plane and stalled dual-stack traffic until the operator re-imported
		// every device; owning the render means refusing to repeat it.
		// client_awg.ipv6: block is the deliberate version of the same route, paired
		// with a master that answers it, so it is allowed there and nowhere else.
		if p.Addr().Is6() && p.Bits() == 0 && m.ClientAWG.IPv6 != ClientIPv6Block {
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

// validateAWG3Secret refuses header protection without a fleet secret to key it on.
//
// Fail closed, and loudly. The alternative — deriving the chacha20 key from the
// public salt when the operator has not set a secret — is exactly the weakness
// this key exists to remove, and it would be invisible: the tunnel comes up, the
// obfuscation looks enabled, and its one secret-bearing parameter is computable by
// anyone holding the source. The 3.x TIMERS need no secret and are unaffected;
// they are the half that carries most of the benefit.
func validateAWG3Secret(c ControllerConfig) []error {
	who := HeaderProtectionEnabledBy(c)
	if len(who) == 0 || c.Fleet.AWG3Key != "" {
		return nil
	}
	return []error{fmt.Errorf("fleet.awg3_key is required because header protection is enabled by %s — "+
		"it is the secret the chacha20 header-protection key is derived from, and deriving that key from "+
		"anything that ships in this repository would defeat it. Set it to a secret:// reference "+
		"(32+ random bytes). AmneziaWG 3.x TIMERS need no secret: use client_awg.awg3: timers for those",
		strings.Join(who, ", "))}
}

// HeaderProtectionEnabledBy lists the manifest keys that switch AmneziaWG 3.x
// header protection on, or nothing when it is off everywhere.
//
// Exported because the answer is needed twice and must not be computed twice
// differently: config validation refuses a missing secret REFERENCE, and startup
// refuses a reference that RESOLVES to nothing. The second check is the one that
// matters — an env var set to the empty string, or an empty secret file, sails
// through the first and yields HMAC with an empty key, which is exactly the
// weakness the fleet secret exists to remove.
func HeaderProtectionEnabledBy(c ControllerConfig) []string {
	var who []string
	if c.Fleet.AWG3 != nil && *c.Fleet.AWG3 {
		who = append(who, "fleet.awg3")
	}
	for i, e := range c.Fleet.Exits {
		if e.AWG3 != nil && *e.AWG3 {
			who = append(who, fmt.Sprintf("fleet.exits[%d] (%s).awg3", i, e.Name))
		}
	}
	for i, m := range c.Fleet.Masters {
		if m.ClientAWG3() == ClientAWG3Full {
			who = append(who, fmt.Sprintf("fleet.masters[%d] (%s).client_awg.awg3: full", i, m.Name))
		}
	}
	return who
}

// MinAWG3KeyLen is the shortest fleet secret accepted for header protection. It
// is a chacha20 key's worth of entropy; anything shorter is a placeholder somebody
// meant to replace.
const MinAWG3KeyLen = 32

// validateClientPoolsDisjoint rejects masters whose client pools overlap. With
// one master this is trivially satisfied; it exists for the multi-master fleet
// (ADR-0027), where an address that belongs to two gateways is ambiguous the
// moment traffic crosses between them — and where the mistake would surface as
// intermittent, hard-to-attribute breakage rather than as a startup error.
// validateAddressPoolsDisjoint rejects overlapping address pools across the WHOLE
// fleet: every exit's pool against every other exit's, and against each master's
// client pool. validateClientPoolsDisjoint below covers master↔master only, and only
// for the multi-master fleet the config rejects one function away — so the topology
// that actually ships was the unvalidated one.
//
// Overlap does not fail loudly. Two exits sharing a pool both hand the master
// TunnelIP .2; mihomo builds two proxies on the same tunnel address and the second
// silently misroutes — intermittent, per-destination, and very hard to trace back to
// a manifest line. An exit pool overlapping a master's client pool breaks the exit's
// masquerade scope the same quiet way.
func validateAddressPoolsDisjoint(f FleetSection) []error {
	type pool struct {
		what   string
		prefix netip.Prefix
	}
	var (
		seen []pool
		errs []error
	)
	add := func(what, cidr string) {
		if cidr == "" {
			return
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return // already reported as a malformed CIDR
		}
		p = p.Masked()
		for _, other := range seen {
			if p.Overlaps(other.prefix) {
				errs = append(errs, fmt.Errorf("address pool %s (%s) overlaps %s (%s)",
					p, what, other.prefix, other.what))
			}
		}
		seen = append(seen, pool{what: what, prefix: p})
	}
	for _, m := range f.Masters {
		add(fmt.Sprintf("masters[%s].client_awg.address_pool", m.Name), m.ClientAWG.AddressPool)
		// The link to mihomo's network namespace is an address pool like any other,
		// and the one an operator is most likely to pick badly: it is a /30 that
		// exists only on the master, so nothing else in the fleet ever mentions it and
		// the collision is invisible until traffic to that range disappears into a
		// namespace. The default (RFC 6598) cannot collide with anything here; an
		// override can land in the middle of a live tunnel.
		add(fmt.Sprintf("masters[%s].mihomo.netns_cidr", m.Name), m.Mihomo.NetnsCIDR)
	}
	for _, e := range f.Exits {
		add(fmt.Sprintf("exits[%s].address_pool", e.Name), e.AddressPool)
		// The lifeline pool is a client-facing pool like the exit's own and the
		// master's, projected by the same controller — it collides the same quiet
		// way (lesson from the two checks above) if left out of this scan.
		if e.Lifeline != nil {
			add(fmt.Sprintf("exits[%s].lifeline.address_pool", e.Name), e.Lifeline.AddressPool)
		}
	}
	return errs
}

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

// validateTunnelReachesItself refuses an exclusion list that cuts clients off
// from their own gateway or resolver.
//
// The natural thing to write here is the list already sitting in the same
// manifest under routing.direct_cidrs — 10/8, 172.16/12, 192.168/16 — and on this
// fleet the client pool and the exits' mgmt addresses (where client DNS lives)
// are both inside 10/8. Subtracting it hands every client a config with no route
// to its own gateway and no route to its resolver: the tunnel connects, nothing
// resolves, and the self-service portal — which lives on a mgmt address — goes
// with it. Nothing downstream can catch this. The expansion is arithmetic and
// produces a perfectly well-formed list; the rendered config is valid; the Web UI
// reports "N networks". It only shows up as a person saying nothing works.
// ClientResolversFromManifest is the resolver list a client of this master will be
// handed, as far as the MANIFEST alone can say.
//
// It exists because the answer used to be derived in two places that then drifted:
// the validator below read only the raw `client_awg.dns` / `compose.client_dns`
// keys, while the broker learned to fall back to ADR-0024's derivation. So a
// manifest that set neither passed validation with no DNS to check, and the broker
// then handed clients a resolver the tunnel did not route to — a config that
// connects and resolves nothing, which reaches the operator as "it doesn't work".
//
// The broker additionally consults the store, because an exit's mgmt address can be
// discovered at registration rather than written down. That case is invisible here
// and is the one gap left: a manifest that omits `mgmt_addr` for an exit cannot be
// checked at startup.
func (f FleetSection) ClientResolversFromManifest(m MasterConfig) []string {
	if dns := m.ClientAWGDNS(); len(dns) > 0 {
		return dns
	}
	if m.DNSFilter {
		// ADR-0024: clients use the master's own address in the client pool.
		if pool, err := netip.ParsePrefix(m.ClientAWG.AddressPool); err == nil {
			if gw := pool.Masked().Addr().Next(); gw.IsValid() {
				return []string{gw.String()}
			}
		}
		return nil
	}
	var out []string
	for _, e := range f.Exits {
		if e.MgmtAddr != "" {
			out = append(out, e.MgmtAddr)
		}
	}
	return out
}

// clientAWGTunnelRoutes parses m's resolved client_awg AllowedIPs into prefixes,
// shared by every check that needs to ask "is address/subnet X still routed into
// this master's tunnel". ok=false on a malformed entry — the caller's own parse
// loop (config.Validate's address_pool/CIDR checks) reports that separately, so
// every caller here treats it as "nothing to say" rather than a second error.
func clientAWGTunnelRoutes(m MasterConfig) (routes []netip.Prefix, ok bool) {
	allowed := m.ClientAWGAllowedIPs()
	routes = make([]netip.Prefix, 0, len(allowed))
	for _, a := range allowed {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return nil, false
		}
		routes = append(routes, p)
	}
	return routes, true
}

// routesCoverAddr reports whether addr is reachable through routes.
func routesCoverAddr(routes []netip.Prefix, addr netip.Addr) bool {
	for _, r := range routes {
		if r.Contains(addr) {
			return true
		}
	}
	return false
}

// routesCoverPrefix reports whether the WHOLE of p is reachable through routes —
// not just its network address, so a route narrower than p (fewer bits, i.e. a
// wider mask) is required, not merely one that happens to contain p's first
// address.
func routesCoverPrefix(routes []netip.Prefix, p netip.Prefix) bool {
	for _, r := range routes {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func validateTunnelReachesItself(i int, m MasterConfig, fleet FleetSection) []error {
	if len(m.ClientAWG.ExcludeFromTunnel) == 0 {
		return nil
	}
	routes, ok := clientAWGTunnelRoutes(m)
	if !ok {
		return nil // reported by the caller's own parse loop
	}

	var errs []error
	if pool, err := netip.ParsePrefix(m.ClientAWG.AddressPool); err == nil {
		if gw := pool.Masked().Addr().Next(); gw.IsValid() && !routesCoverAddr(routes, gw) {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.exclude_from_tunnel removes %s "+
				"(the client pool, and %s is the gateway clients talk to) from the tunnel — add it to "+
				"client_awg.route_through_cidrs", i, m.ClientAWG.AddressPool, gw))
		}
	}
	for _, d := range fleet.ClientResolversFromManifest(m) {
		addr, err := netip.ParseAddr(d)
		if err != nil {
			continue // reported by the caller's own parse loop
		}
		if !routesCoverAddr(routes, addr) {
			errs = append(errs, fmt.Errorf("fleet.masters[%d]: client_awg.exclude_from_tunnel removes the "+
				"client DNS server %s from the tunnel — clients would resolve nothing; add its network to "+
				"client_awg.route_through_cidrs", i, d))
		}
	}
	return errs
}

// ClientAWGTunnelWarnings flags every master whose client_awg.exclude_from_tunnel
// would leave the client portal (controller.client_portal's own bind address) or
// the management overlay outside the AllowedIPs a client actually gets — a device
// that has fallen back to AWG can then never reach the portal to refresh its mihomo
// subscription (mihomo/clientprofile.go, config/client_wg.go's own exclude_from_tunnel
// expansion), and nothing else in the manifest would ever say so.
//
// Unlike validateTunnelReachesItself, this is advisory only and is NEVER folded
// into Validate's joined error: a hard refusal here could stop a live controller on
// upgrade over a tunnel shape that has otherwise run fine for months. Callers log
// each returned line as a WARN at startup/config load instead.
func ClientAWGTunnelWarnings(c ControllerConfig) []string {
	portalAddr, havePortal := portalBindAddr(c.Controller.ClientPortal)
	mgmtCIDRs := c.Fleet.MgmtCIDRs()

	var warnings []string
	for i, m := range c.Fleet.Masters {
		if len(m.ClientAWG.ExcludeFromTunnel) == 0 {
			continue
		}
		routes, ok := clientAWGTunnelRoutes(m)
		if !ok {
			continue // reported by the caller's own parse loop
		}
		if havePortal && !routesCoverAddr(routes, portalAddr) {
			warnings = append(warnings, fmt.Sprintf("fleet.masters[%d] (%s): client_awg.exclude_from_tunnel removes "+
				"the client portal's bind address %s from the tunnel — a device that falls back to AWG can never "+
				"refresh its mihomo subscription there; add it (or its network) to client_awg.route_through_cidrs",
				i, m.Name, portalAddr))
		}
		for _, cidr := range mgmtCIDRs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			if !routesCoverPrefix(routes, p) {
				warnings = append(warnings, fmt.Sprintf("fleet.masters[%d] (%s): client_awg.exclude_from_tunnel removes "+
					"the management overlay %s from the tunnel — a device on AWG alone can never reach the portal or "+
					"any other admin surface bound there; add it to client_awg.route_through_cidrs", i, m.Name, cidr))
			}
		}
	}
	return warnings
}

// portalBindAddr parses controller.client_portal's host into an address to check
// tunnel coverage against. ok=false when the bind is unset or unparseable — a
// malformed bind is reported by validateClientPortal, not repeated here.
func portalBindAddr(bind string) (netip.Addr, bool) {
	if bind == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// Client-facing IPv6 modes for client_awg.ipv6.
const (
	// ClientIPv6Off tells the client nothing about IPv6. Its own native v6 keeps
	// working and keeps bypassing the tunnel.
	ClientIPv6Off = "off"
	// ClientIPv6Block hands the client ::/0 and has the master refuse it audibly.
	ClientIPv6Block = "block"
)
