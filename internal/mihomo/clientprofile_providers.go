package mihomo

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The provider form of the device profile. The AmneziaWG proxies live in a proxy
// provider the core re-fetches every hour on its own, whether or not the app ever
// refreshes the profile; a change to their keys or generation reaches the device
// within that hour without anyone touching it. VLESS stays in the profile, as an
// inline provider: AmneziaWG changes never touch it, so it is the stable path
// the AmneziaWG provider is fetched over when the old AmneziaWG proxies stopped
// working.
//
// Group shapes (measured on mihomo 1.19.33):
//   - VLESS is an inline provider, not a top-level proxy: a group lists its
//     `proxies:` before its `use:`, so a top-level VLESS would sit in front of
//     every AmneziaWG proxy.
//   - The provider's `proxy:` names a group: a proxy that lives in a provider
//     is not found by name.
//   - Every group ends with a reject proxy: a group whose providers are all empty
//     (the first fetch failed and the master has no VLESS) becomes COMPATIBLE,
//     which is DIRECT — the device's traffic would leave beside the tunnel.
//   - Health checks stay on the groups; a group checks the provider proxies it
//     uses at its own interval.

const (
	ClientProviderAWG        = "wgfleet-awg"
	ClientProviderVLESS      = "wgfleet-vless"
	ClientProviderLastResort = "wgfleet-vless-last-resort"
	ClientProviderGuard      = "wgfleet-guard"
	// ClientProfileBlockedProxy is the reject proxy that closes every group.
	ClientProfileBlockedProxy = "wgfleet-blocked"
	// ClientProviderInterval is how often the core re-fetches the AmneziaWG
	// provider, in seconds: the longest a device runs on keys the fleet replaced.
	// It is also the retry delay of a fetch that failed — the core has no other
	// retry — and the first fetch, made over VLESS before any AmneziaWG proxy
	// exists, is the one that can fail. A few KB per device per quarter hour.
	ClientProviderInterval = 900
)

// providerMaster is one master's proxies, by name, in the order the inline
// profile lists them.
type providerMaster struct {
	name       string
	awg, vless []string
	lastResort bool
}

// providerLayout builds the proxy-providers block and the groups that use them.
// sites are the site switches, placed where the inline profile has them.
func providerLayout(url string, masters []providerMaster, byName map[string]any, sites []any) (map[string]any, []any) {
	var awg, vless, lastResort []any
	for _, m := range masters {
		for _, n := range m.awg {
			awg = append(awg, byName[n])
		}
		for _, n := range m.vless {
			if m.lastResort {
				lastResort = append(lastResort, byName[n])
			} else {
				vless = append(vless, byName[n])
			}
		}
	}
	providers := map[string]any{
		ClientProviderGuard: map[string]any{"type": "inline", "payload": []any{
			map[string]any{"name": ClientProfileBlockedProxy, "type": "reject"},
		}},
	}
	// The order of `use` is the order of the group: AmneziaWG, VLESS, the
	// last-resort VLESS. An inline provider with nothing in it is left out.
	var use []string
	if len(awg) > 0 {
		providers[ClientProviderAWG] = map[string]any{
			"type":     "http",
			"url":      url,
			"interval": ClientProviderInterval,
			// Through the device's own fallback: whichever path is alive, VLESS
			// when the old AmneziaWG proxies no longer reach the master.
			"proxy": ClientProfileAutoGroup,
		}
		use = append(use, ClientProviderAWG)
	}
	if len(vless) > 0 {
		providers[ClientProviderVLESS] = map[string]any{"type": "inline", "payload": vless}
		use = append(use, ClientProviderVLESS)
	}
	if len(lastResort) > 0 {
		providers[ClientProviderLastResort] = map[string]any{"type": "inline", "payload": lastResort}
		use = append(use, ClientProviderLastResort)
	}
	guarded := append(append([]string(nil), use...), ClientProviderGuard)

	var groups []any
	for _, m := range masters {
		g := fallbackGroup(m.name, nil, ClientProfileMasterHealthInterval)
		delete(g, "proxies")
		g["use"] = toAnySlice(guarded)
		g["filter"] = exactNames(append(append(append([]string(nil), m.awg...), m.vless...), ClientProfileBlockedProxy))
		groups = append(groups, g)
	}
	groups = append(groups, sites...)
	auto := fallbackGroup(ClientProfileAutoGroup, nil, ClientProfileHealthInterval)
	delete(auto, "proxies")
	auto["use"] = toAnySlice(guarded)
	groups = append(groups, auto, map[string]any{
		"name": ClientProfileSelectGroup,
		"type": "select",
		// auto first, as in the inline profile: `proxies:` come before `use:`.
		// No reject proxy here — auto is always a member, so the group is never empty.
		"proxies": []any{ClientProfileAutoGroup},
		"use":     toAnySlice(use),
	})
	return providers, groups
}

// exactNames is a filter matching these proxy names and nothing else. A prefix
// such as "^m1-" would also take the proxies of a master named "m1-x".
func exactNames(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return "^(?:" + strings.Join(q, "|") + ")$"
}

// providerFormFits reports whether the provider form can bootstrap: the provider
// lives on the portal, reached only through the tunnel, and until its first
// fetch the profile has no AmneziaWG proxy to reach it over. Without VLESS on
// any master the device could never fetch it, and gets the inline form instead.
func providerFormFits(masters []providerMaster) bool {
	for _, m := range masters {
		if len(m.vless) > 0 {
			return true
		}
	}
	return false
}

// RenderClientProviderProxies renders the AmneziaWG provider a provider-form
// profile points at: the device's AmneziaWG proxies, masters in manifest order,
// built by the same code as the inline profile's.
func RenderClientProviderProxies(in ClientProfileInput) (string, error) {
	var proxies []any
	for _, m := range in.Masters {
		if m.AWG == nil {
			continue
		}
		p, err := clientWireguardProxy(m.Name+"-awg", *m.AWG)
		if err != nil {
			return "", fmt.Errorf("client provider: master %q: %w", m.Name, err)
		}
		proxies = append(proxies, p)
	}
	if len(proxies) == 0 {
		return "", errors.New("client provider: no AmneziaWG proxy to render")
	}
	return marshalYAML(map[string]any{"proxies": proxies})
}
