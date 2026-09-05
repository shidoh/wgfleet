package health

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dnsProbeName is what the probe asks for. A name with a short, stable TTL served
// by many anycast nodes, so a failure is about the path rather than about one
// authoritative server having a bad day.
const dnsProbeName = "cloudflare.com."

// dnsProbeTimeout bounds one query. Deliberately short: this runs inside a
// reconcile pass, and a resolver that needs longer than this has already failed
// from a client's point of view.
const dnsProbeTimeout = 3 * time.Second

// QueryDNSOverUDP asks one named resolver, over UDP, for an address record —
// bypassing /etc/resolv.conf entirely.
//
// Bypassing it is the whole point. The client-path prober's original DNS probe
// ran `getent`, which reads the host's resolv.conf, where the fleet's own
// resolver is the client gateway — so the query never left the tunnel, never
// reached mihomo, and never touched the TPROXY reply path. It was green
// throughout the eight days client UDP was one-way. A probe that cannot fail on
// the failure it is named after is not a probe.
//
// Pure Go, and stdlib only: the pure-Go resolver plus a Dial that ignores the
// configured servers is the whole mechanism, so this needs no dig, no dnsutils
// package, and no assumption about what is installed on a node.
func QueryDNSOverUDP(ctx context.Context, server string) error {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return fmt.Errorf("dns probe: server %q must be host:port: %w", server, err)
	}
	ctx, cancel := context.WithTimeout(ctx, dnsProbeTimeout)
	defer cancel()

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// UDP, always, and to the server we were given rather than the one the
			// system would choose. The network argument is discarded on purpose: Go
			// would ask for "udp" first and retry over "tcp" on a truncated answer, and
			// a TCP retry would measure a different path than the one under test.
			var d net.Dialer
			return d.DialContext(ctx, "udp", server)
		},
	}
	addrs, err := r.LookupHost(ctx, dnsProbeName)
	if err != nil {
		return fmt.Errorf("dns probe: %s did not answer over UDP: %w", server, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("dns probe: %s answered with no addresses", server)
	}
	return nil
}
