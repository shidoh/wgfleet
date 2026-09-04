package master

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/netns"
)

// ClientPathProbe is one measurement of the client path, taken from inside the
// prober's namespace so it traverses exactly what a client's traffic traverses:
// the AmneziaWG interface, the nftables chains, mihomo, an exit, and back.
type ClientPathProbe struct {
	Name string // what was measured, e.g. "tcp/443"
	OK   bool
	Why  string // empty when OK
}

// clientPathTimeout bounds one probe. Short: this runs inside a reconcile pass
// whose whole budget is 30 seconds, and a path that needs longer than this to
// answer is already failing from a user's point of view.
const clientPathTimeout = 5 * time.Second

// MeasureClientPath runs the probes that answer the one question no component
// metric answers: does a packet entering the client interface come back.
//
// Every component signal was green for the eight days client QUIC was dead —
// master↔exit at 0% loss, exit→WARP at 30 MB/s, every proxy alive, no failed
// units — because each of them measured a component and every component was fine.
// The sentence nobody was checking is this one.
//
// What is deliberately NOT here: an end-to-end UDP/443 probe. Nothing on the
// public internet answers an arbitrary datagram on 443 — a QUIC server needs a
// valid Initial, which is not something a probe can craft with the tools on a
// node. That gap is covered from the other side instead, by the bind probe
// (health.UDPReturnBindable), which asserts a reply socket is possible for that
// port; between them, "UDP works through the tunnel" and "no port black-holes"
// cover the failure this exists for.
func MeasureClientPath(ctx context.Context, gateway string, run netns.Runner) []ClientPathProbe {
	if run == nil {
		run = netns.Exec
	}
	if gateway == "" {
		// Without the client gateway there is no tunnel-only probe, and the remaining
		// two cannot be told apart from an upstream failure. Report nothing rather
		// than something ambiguous.
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 4*clientPathTimeout)
	defer cancel()

	timeout := fmt.Sprint(int(clientPathTimeout.Seconds()))
	checks := []struct {
		name string
		argv []string
	}{
		// The gateway first, and it earns its place by being the discriminator. It
		// proves the tunnel itself — encrypt, cross the client interface, decrypt —
		// without depending on the resolver, the proxy or an exit. When this passes
		// and the others fail, the client leg is fine and something beyond it is not;
		// when this fails, nothing further is worth reading. Working that out by hand
		// took a stand session, which is a good reason for the metric to say it.
		{"icmp/gateway", []string{"ping", "-c", "2", "-W", "2", "-q", gateway}},
		// TCP through the tunnel, through mihomo, to an exit and out. The same URL
		// the tier prober uses, so a failure here and a failure there are comparable.
		{"tcp/443", []string{"curl", "-sS", "-o", "/dev/null", "--max-time", timeout,
			"https://cp.cloudflare.com/generate_204"}},
		// UDP through the tunnel. DNS on 53 rather than QUIC on 443 for the reason in
		// the doc comment: something has to answer, and a resolver does.
		{"udp/53", []string{"timeout", timeout, "getent", "ahostsv4", "cloudflare.com"}},
	}

	out := make([]ClientPathProbe, 0, len(checks))
	for _, c := range checks {
		argv := append([]string{"netns", "exec", synthNetns}, c.argv...)
		if _, err := run(ctx, "ip", argv...); err != nil {
			out = append(out, ClientPathProbe{Name: c.name, Why: trimProbeError(err)})
			continue
		}
		out = append(out, ClientPathProbe{Name: c.name, OK: true})
	}
	return out
}

// ClientPathOK reports whether every probe passed. An empty set is NOT ok: it
// means nothing was measured, and reporting that as healthy is how a prober
// becomes a source of false confidence.
func ClientPathOK(probes []ClientPathProbe) bool {
	if len(probes) == 0 {
		return false
	}
	for _, p := range probes {
		if !p.OK {
			return false
		}
	}
	return true
}

// trimProbeError keeps a probe failure readable in a log line.
//
// It caps the length and nothing else. An earlier version kept only the text
// after the last ": ", which on a real failure left the single word
// "cp.cloudflare.com" — the host name, with the actual error ("Could not resolve
// host") discarded. A message that drops the reason is worse than a long one.
func trimProbeError(err error) string {
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}
