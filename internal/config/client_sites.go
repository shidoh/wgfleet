package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// ClientSiteConfig is one entry of fleet.client_sites: a network that is the
// device's own LAN in one place and far away in another (home, office). The
// device profile reaches it DIRECT when ProbeURL answers directly and through
// the tunnel when it does not, with a manual switch on top.
type ClientSiteConfig struct {
	Name  string   `koanf:"name"`
	CIDRs []string `koanf:"cidrs"`
	// ProbeURL must be http:// on an IP inside CIDRs: a name would need DNS, and
	// the fleet resolver answers through the very tunnel the probe decides about.
	ProbeURL      string `koanf:"probe_url"`
	ProbeInterval int    `koanf:"probe_interval"`
}

const (
	minSiteProbeInterval = 10
	maxSiteProbeInterval = 3600
)

// ClientSitesSpec is what the device profile renders from.
func (f FleetSection) ClientSitesSpec() []domain.ClientSite {
	out := make([]domain.ClientSite, 0, len(f.ClientSites))
	for _, s := range f.ClientSites {
		out = append(out, domain.ClientSite{
			Name:          s.Name,
			CIDRs:         canonicalCIDRs(s.CIDRs),
			ProbeURL:      s.ProbeURL,
			ProbeInterval: s.ProbeInterval,
		})
	}
	return out
}

// canonicalCIDRs renders what validation parsed, not the raw manifest string:
// no stray whitespace or host bits in a rule mihomo has to parse.
func canonicalCIDRs(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			out = append(out, p.Masked().String())
		}
	}
	return out
}

// validateClientSites checks names against everything the profile already
// calls something, and nets against the two ranges a site must never capture:
// the mgmt overlay (the portal lives there) and a client pool (the tunnel's own
// addresses).
func validateClientSites(f FleetSection) []error {
	var errs []error
	taken := map[string]bool{"auto": true, "wgfleet": true, "DIRECT": true, "REJECT": true}
	for _, m := range f.Masters {
		taken[m.Name], taken[m.Name+"-awg"], taken[m.Name+"-vless"] = true, true, true
	}
	for _, s := range f.ClientSites {
		taken[s.Name+"-auto"] = true
	}
	var claimed []sitePrefix
	for i, s := range f.ClientSites {
		where := fmt.Sprintf("fleet.client_sites[%d]", i)
		switch {
		case s.Name == "":
			errs = append(errs, fmt.Errorf("%s: name is required", where))
		case strings.ContainsAny(s.Name, ",#"):
			errs = append(errs, fmt.Errorf("%s: name %q contains ',' or '#', which mihomo reads as syntax", where, s.Name))
		case taken[s.Name]:
			errs = append(errs, fmt.Errorf("%s: name %q collides with a master, proxy, group or policy of the device profile", where, s.Name))
		}
		// The auto group this site adds must not be a name the profile already
		// uses either: a master named "home-auto" would share its group with it.
		for _, m := range f.Masters {
			if s.Name != "" && m.Name == s.Name+"-auto" {
				errs = append(errs, fmt.Errorf("%s: the site's group %q collides with master %q", where, s.Name+"-auto", m.Name))
			}
		}
		taken[s.Name] = true
		prefixes, perr := validateSiteCIDRs(where, s.CIDRs, f, claimed)
		errs = append(errs, perr...)
		for _, p := range prefixes {
			claimed = append(claimed, sitePrefix{site: s.Name, prefix: p})
		}
		errs = append(errs, validateSiteProbe(where, s, prefixes)...)
	}
	return errs
}

type sitePrefix struct {
	site   string
	prefix netip.Prefix
}

// forcedThrough is every route_through_cidrs entry of every master: nets the
// operator sends into the tunnel on purpose. A site's rule comes first in the
// profile, so a site overlapping one would take that range DIRECT whenever the
// probe answers.
func forcedThrough(f FleetSection) []netip.Prefix {
	var out []netip.Prefix
	for _, m := range f.Masters {
		for _, c := range append(append([]string(nil), m.ClientAWG.RouteThroughCIDRs...), m.ClientVLESS.RouteThroughCIDRs...) {
			if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

func validateSiteCIDRs(where string, cidrs []string, f FleetSection, claimed []sitePrefix) ([]netip.Prefix, []error) {
	if len(cidrs) == 0 {
		return nil, []error{fmt.Errorf("%s: cidrs needs at least one network", where)}
	}
	var (
		prefixes []netip.Prefix
		errs     []error
	)
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: cidrs entry %q is not a valid CIDR: %w", where, c, err))
			continue
		}
		if !p.Addr().Is4() {
			// The client data plane is IPv4-only, and the rule it
			// renders into is IP-CIDR, not IP-CIDR6.
			errs = append(errs, fmt.Errorf("%s: cidrs entry %q is not IPv4", where, c))
			continue
		}
		p = p.Masked()
		prefixes = append(prefixes, p)
		for _, q := range forcedThrough(f) {
			if p.Overlaps(q) {
				errs = append(errs, fmt.Errorf("%s: %s overlaps route_through_cidrs %s — the site would take that range DIRECT", where, p, q))
			}
		}
		for _, o := range claimed {
			if p.Overlaps(o.prefix) {
				errs = append(errs, fmt.Errorf("%s: %s overlaps %s of site %q", where, p, o.prefix, o.site))
			}
		}
		for _, mg := range f.MgmtCIDRs() {
			if q, err := netip.ParsePrefix(mg); err == nil && p.Overlaps(q) {
				errs = append(errs, fmt.Errorf("%s: %s overlaps the mgmt overlay %s (fleet.mgmt_subnet) — the portal lives there", where, p, q))
			}
		}
		for _, m := range f.Masters {
			if q, err := netip.ParsePrefix(m.ClientAWG.AddressPool); err == nil && p.Overlaps(q) {
				errs = append(errs, fmt.Errorf("%s: %s overlaps the client pool %s of %q (client_awg.address_pool)", where, p, q, m.Name))
			}
		}
	}
	return prefixes, errs
}

func validateSiteProbe(where string, s ClientSiteConfig, prefixes []netip.Prefix) []error {
	if s.ProbeURL == "" {
		if s.ProbeInterval != 0 {
			return []error{fmt.Errorf("%s: probe_interval is set without probe_url", where)}
		}
		return nil
	}
	var errs []error
	if s.ProbeInterval != 0 && (s.ProbeInterval < minSiteProbeInterval || s.ProbeInterval > maxSiteProbeInterval) {
		errs = append(errs, fmt.Errorf("%s: probe_interval %d out of range (0 for default, else %d..%d)",
			where, s.ProbeInterval, minSiteProbeInterval, maxSiteProbeInterval))
	}
	u, err := url.Parse(s.ProbeURL)
	if err != nil || u.Scheme != "http" {
		return append(errs, fmt.Errorf("%s: probe_url %q must be an http:// URL", where, s.ProbeURL))
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !addr.Is4() {
		return append(errs, fmt.Errorf("%s: probe_url host %q must be an IPv4 address inside cidrs", where, u.Hostname()))
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return errs
		}
	}
	return append(errs, fmt.Errorf("%s: probe_url address %s is outside the site's cidrs", where, addr))
}
