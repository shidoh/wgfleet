package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// LifelineConfig is a reserve client-facing AmneziaWG interface on an exit: a
// second, independent way in for clients if the master's own client interface is
// ever unreachable. It is opt-in (nil ⇒ off) and deliberately narrow — a listener,
// a pool, an egress choice, resolvers and an MTU — because it exists purely as a
// fallback path, not a second client-facing product surface to keep in parity with
// the master's.
type LifelineConfig struct {
	ListenPort  int      `koanf:"listen_port"`
	AddressPool string   `koanf:"address_pool"`
	Egress      string   `koanf:"egress"` // "" | direct | warp
	DNS         []string `koanf:"dns"`
	MTU         int      `koanf:"mtu"`
	// AllowedIPs overrides what a reserve config routes into the tunnel. Unset ⇒
	// 0.0.0.0/0, which is both the simplest thing for a fallback profile to do and
	// the only shape wg-quick handles correctly on a client — see
	// keybroker.lifelineAllowedIPs for what a split list costs there. IPv4 only.
	AllowedIPs []string `koanf:"allowed_ips"`
}

// LifelineEnabled reports whether this exit carries a reserve client-facing
// interface. A nil section means the exit is unchanged from before this feature
// existed — no reserve path, exactly the pre-lifeline behaviour.
func (e ExitConfig) LifelineEnabled() bool { return e.Lifeline != nil }

// ResolvedEgress returns the lifeline's egress method, defaulting an unset value
// to direct: a reserve path that exists to work when the master is unreachable
// should not, by default, ALSO depend on the exit's WARP leg being healthy.
func (l LifelineConfig) ResolvedEgress() domain.EgressMethod {
	if strings.TrimSpace(l.Egress) == "" {
		return domain.EgressDirect
	}
	return domain.EgressMethod(strings.ToLower(strings.TrimSpace(l.Egress)))
}

// exitEgressChainHas reports whether m is somewhere in the exit's egress chain —
// its preferred egress or one of its ADR-0017 fallbacks.
func exitEgressChainHas(e ExitConfig, m domain.EgressMethod) bool {
	if e.Egress == string(m) {
		return true
	}
	for _, f := range e.EgressFallback {
		if f == string(m) {
			return true
		}
	}
	return false
}

// validateLifeline checks every exit's opt-in lifeline section. Each finding
// names the manifest path it came from (fleet.exits[<name>].lifeline...) so a
// misconfigured reserve interface fails loudly at startup instead of quietly
// never coming up (or coming up unreachable) the day it is actually needed.
func (c ControllerConfig) validateLifeline() []error {
	var errs []error
	master, hasMaster := c.Fleet.BaseMaster()
	masterPool, _ := netip.ParsePrefix(master.ClientAWG.AddressPool) // invalid ⇒ zero Prefix, IsValid() false below

	for i, e := range c.Fleet.Exits {
		l := e.Lifeline
		if l == nil {
			continue
		}
		at := fmt.Sprintf("fleet.exits[%s].lifeline", e.Name)

		// The exit's NAME is a path segment in every reserve URL the portal hands out
		// ("/c/<token>/l/<exit>/config"), and the portal bounds that segment before it
		// looks anything up. A name outside those bounds makes the console and the
		// self-service page list a door whose download and QR both 404 — and both are
		// charged to the reader's rate limit, so a handful of auto-loaded QR images
		// locks them out of their own working profile. Only exits that actually carry
		// a lifeline are held to it: elsewhere the name fronts no URL.
		if !domain.ValidLifelineExitName(e.Name) {
			errs = append(errs, fmt.Errorf("%s: the exit name %q cannot appear in a reserve config URL — want %s",
				at, e.Name, domain.LifelineExitNameCharset))
		}

		if l.ListenPort <= 0 || l.ListenPort > 65535 {
			errs = append(errs, fmt.Errorf("%s.listen_port %d out of range", at, l.ListenPort))
		}
		if l.ListenPort == e.WGListenPort() {
			errs = append(errs, fmt.Errorf("%s.listen_port %d equals the exit listen_port", at, l.ListenPort))
		}
		for _, p := range e.Firewall.PublicUDPPorts {
			if p == l.ListenPort {
				errs = append(errs, fmt.Errorf("%s.listen_port %d is already listed in firewall.public_udp_ports", at, p))
			}
		}

		switch p, err := netip.ParsePrefix(l.AddressPool); {
		case l.AddressPool == "":
			errs = append(errs, fmt.Errorf("%s.address_pool is required", at))
		case err != nil:
			errs = append(errs, fmt.Errorf("%s.address_pool %q: %w", at, l.AddressPool, err))
		case !p.Addr().Is4():
			errs = append(errs, fmt.Errorf("%s.address_pool %q must be IPv4", at, l.AddressPool))
		case hasMaster && masterPool.IsValid() && p.Bits() > masterPool.Bits():
			errs = append(errs, fmt.Errorf("%s.address_pool %s must be at least as large as the master client pool %s",
				at, p.Masked(), masterPool.Masked()))
		}

		for _, a := range l.AllowedIPs {
			switch p, err := netip.ParsePrefix(a); {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s.allowed_ips %q: %w", at, a, err))
			case !p.Addr().Is4():
				// The lifeline spec carries no IPv6 prefix for the interface to answer
				// from, so a v6 route here is a route to a black hole.
				errs = append(errs, fmt.Errorf("%s.allowed_ips %q must be IPv4", at, a))
			}
		}

		switch l.ResolvedEgress() {
		case domain.EgressDirect:
		case domain.EgressWARP:
			if !exitEgressChainHas(e, domain.EgressWARP) {
				errs = append(errs, fmt.Errorf("%s.egress: WARP is not in this exit's egress chain", at))
			}
		default:
			errs = append(errs, fmt.Errorf("%s.egress %q: want direct or warp", at, l.Egress))
		}

		// Without dns_filter the exit's own blocky is the only resolver a lifeline
		// client can reach — the master, which normally supplies DNS, is by
		// definition the thing this reserve path exists to work around.
		if len(l.DNS) == 0 && !e.DNSFilter {
			errs = append(errs, fmt.Errorf("%s.dns is required when dns_filter is off (the master's resolvers are unreachable without the master)", at))
		}

		// The lifeline pool is projected by the controller, the same way the master's
		// client pool is, so it needs the master whose clients it carries.
		if !hasMaster {
			errs = append(errs, fmt.Errorf("fleet.exits[%d] (%s): lifeline needs a master in slot 0 (its clients are the ones a lifeline carries)", i, e.Name))
		}
		if hasMaster && !master.ClientAWGEnabled() {
			errs = append(errs, fmt.Errorf("%s: requires masters[%s].client_awg.address_pool (the lifeline carries that master's clients)", at, master.Name))
		}
	}
	return errs
}
