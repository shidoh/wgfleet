package mihomo

import (
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// ClientSiteProbeInterval is how often, in seconds, a site's fallback re-checks
// its probe when the manifest does not say. After a move it also re-checks on
// its own once dials through the stale choice keep failing.
const ClientSiteProbeInterval = 60

// siteAutoGroup names the fallback that guesses "here or away" for one site.
func siteAutoGroup(site string) string { return site + "-auto" }

// validateSiteNames refuses a site whose name, or whose auto group's name, is
// already a group, proxy or built-in policy of this profile — a collision would
// silently route one of them through the other.
func validateSiteNames(sites []domain.ClientSite, masters []ClientProfileMaster) error {
	taken := map[string]bool{}
	for _, m := range masters {
		taken[m.Name], taken[m.Name+"-awg"], taken[m.Name+"-vless"] = true, true, true
	}
	for _, s := range sites {
		taken[siteAutoGroup(s.Name)] = true
	}
	masterNames := map[string]bool{}
	for _, m := range masters {
		masterNames[m.Name] = true
	}
	seen := map[string]bool{}
	for _, s := range sites {
		if masterNames[siteAutoGroup(s.Name)] {
			return fmt.Errorf("client profile: site %q adds group %q, which is a master's name", s.Name, siteAutoGroup(s.Name))
		}
		switch {
		case s.Name == "":
			return fmt.Errorf("client profile: a site has no name")
		case strings.ContainsAny(s.Name, ",#"):
			return fmt.Errorf("client profile: site name %q contains ',' or '#', which mihomo reads as syntax", s.Name)
		case isReservedProfileName(s.Name), taken[s.Name], seen[s.Name]:
			return fmt.Errorf("client profile: site name %q collides with a group, proxy or policy of the profile", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// siteGroups renders each site's switch: a select the person can flip, over a
// fallback that picks DIRECT while the probe answers directly and the tunnel
// when it does not. Without a probe the switch is manual, DIRECT by default —
// what the profile did for these nets before sites existed.
func siteGroups(sites []domain.ClientSite) []any {
	var groups []any
	for _, s := range sites {
		choices := []string{"DIRECT", ClientProfileSelectGroup}
		if s.ProbeURL != "" {
			interval := s.ProbeInterval
			if interval <= 0 {
				interval = ClientSiteProbeInterval
			}
			groups = append(groups, map[string]any{
				"name":     siteAutoGroup(s.Name),
				"type":     "fallback",
				"proxies":  toAnySlice(choices),
				"url":      s.ProbeURL,
				"interval": interval,
			})
			choices = append([]string{siteAutoGroup(s.Name)}, choices...)
		}
		groups = append(groups, map[string]any{
			"name":    s.Name,
			"type":    "select",
			"proxies": toAnySlice(choices),
		})
	}
	return groups
}

// siteRules come before every other rule: site nets are RFC1918 and may sit
// inside route_through_cidrs, and either broader rule would swallow them.
func siteRules(sites []domain.ClientSite) []string {
	var rules []string
	for _, s := range sites {
		for _, c := range s.CIDRs {
			rules = append(rules, "IP-CIDR,"+c+","+s.Name)
		}
	}
	return rules
}
