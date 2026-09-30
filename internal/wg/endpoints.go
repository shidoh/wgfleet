package wg

import "strings"

// ParseShowEndpoints reads `awg show <iface> endpoints` (and `wg show`, same
// format): one "<public key>\t<endpoint>" line per peer, "(none)" when the peer
// has no endpoint yet. Peers without one are omitted.
func ParseShowEndpoints(out string) map[string]string {
	eps := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, ep, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || ep == "" || ep == "(none)" {
			continue
		}
		eps[key] = ep
	}
	return eps
}
