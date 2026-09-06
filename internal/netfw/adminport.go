package netfw

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// clashAPIEndpoint parses mihomo's external-controller address into the pieces the
// host NAT needs: a canonical IP and a port. Anything that is not host:port with a
// literal IP and a valid port is reported as absent rather than as an error — the
// API address is optional, and an unparseable one must render the same ruleset as
// none at all, not a different one.
func clashAPIEndpoint(clashAPI string) (addr string, port int, ok bool) {
	host, p, err := net.SplitHostPort(clashAPI)
	if err != nil {
		return "", 0, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, false
	}
	return ip.String(), n, true
}

// ClientForwardedPorts is the ONE answer to "which of mihomo's ports does the host
// forward into the namespace on behalf of clients": the Clash API port, and only
// when the operator has put it in client_admin_ports.
//
// Two rulesets depend on this answer. The host's NAT opens the door — a DNAT from
// the client interface to the namespace address — and the namespace's input
// closure decides what a client may reach on that address. Rendered from two
// separate readings of the spec they drifted within a day: the host forwarded 9090,
// the closure admitted only the redirect port, and every client SYN to the
// dashboard died one hop past the rule that let it in (live master 2026-09-06,
// 2097 drops, conntrack full of UNREPLIED entries). Same failure shape as the
// REALITY outage: two renderers, one fact, two sources. Hence one function.
func ClientForwardedPorts(clashAPI string, clientAdminPorts []int) []int {
	_, port, ok := clashAPIEndpoint(clashAPI)
	if !ok {
		return nil
	}
	for _, p := range clientAdminPorts {
		if p == port {
			return []int{port}
		}
	}
	return nil
}

// tcpPortSet renders one or more ports for a `tcp dport` match: a bare number for
// one, an anonymous set for several. Sorted and de-duplicated so the same input
// always renders the same bytes — a reconcile pass compares rendered files.
func tcpPortSet(ports ...int) string {
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if p > 0 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	if len(out) == 1 {
		return strconv.Itoa(out[0])
	}
	s := "{ "
	for i, p := range out {
		if i > 0 {
			s += ", "
		}
		s += strconv.Itoa(p)
	}
	return s + " }"
}
