package master

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
	// Decisive says whether this probe is allowed to revert a migration on its own.
	//
	// The distinction is not bureaucracy. The automatic revert is driven by this
	// set, and a probe that depends on somebody else's uptime — an exit that may be
	// draining, a public endpoint that may be having a bad hour — would spend one of
	// three attempts every time a third party sneezed, and a node that spends all
	// three is terminal until a human looks. Decisive probes are the ones whose
	// failure can only mean THIS node broke.
	Decisive bool
}

// clientPathTimeout bounds one probe. Short: this runs inside a reconcile pass
// whose whole budget is 30 seconds, and a path that needs longer than this to
// answer is already failing from a user's point of view.
const clientPathTimeout = 5 * time.Second

// DNSProbeFlag is the agent flag that turns the binary into a one-shot UDP DNS
// probe. Declared here, next to the code that builds the command line, so the
// flag and its only caller cannot drift apart.
const DNSProbeFlag = "-dns-probe"

// UDPReturnScanFlag is the agent flag that turns the binary into a one-shot
// UDP-return scan of the namespace it is started in.
const UDPReturnScanFlag = "-udp-return-scan"

// defaultResolvers are the external resolvers the UDP probe may use, tried in
// order. Two operators rather than one: a probe that reverts a migration because
// a single provider had an outage is a probe that manufactures outages.
var defaultResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// defaultProbeURLs are the TCP targets, likewise two.
var defaultProbeURLs = []string{
	"https://cp.cloudflare.com/generate_204",
	"https://www.gstatic.com/generate_204",
}

// ClientPathTargets is what the prober aims at. Every field is optional except
// the gateway; a missing target means one fewer probe, never a failing one.
type ClientPathTargets struct {
	// Gateway is the master's own address in the client pool — what a client sends
	// its DNS to, and what proves the tunnel itself.
	Gateway string
	// MgmtAddr is the master's management-overlay address. It is on this host, so
	// it always answers when the path to it is right — which makes it the one
	// destination that can tell "traffic that must BYPASS the interception still
	// does" without depending on anything outside this node.
	MgmtAddr string
	// Direct are destinations the client is supposed to reach without going through
	// an exit: exit public IPs, corporate networks. They are probed because moving
	// interception into a namespace takes the whole client interface with it, and
	// the destination-based exemptions that keep these direct live somewhere the
	// move does not automatically carry.
	Direct []string
	// SelfExec is this agent's own binary. It is re-executed inside the prober's
	// namespace to take the UDP probe, because nothing installed on a stock node
	// can send a DNS query to a NAMED server without reading resolv.conf first —
	// and reading resolv.conf is precisely what makes the probe miss.
	SelfExec string
}

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
func MeasureClientPath(ctx context.Context, t ClientPathTargets, run netns.Runner) []ClientPathProbe {
	if run == nil {
		run = netns.Exec
	}
	if t.Gateway == "" {
		// Without the client gateway there is no tunnel-only probe, and the remaining
		// ones cannot be told apart from an upstream failure. Report nothing rather
		// than something ambiguous.
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*clientPathTimeout)
	defer cancel()

	timeout := fmt.Sprint(int(clientPathTimeout.Seconds()))
	var out []ClientPathProbe
	// try runs the attempts in order and passes on the first that works. Several
	// targets per probe, one verdict: what is being measured is this node's path,
	// and a single unreachable third party is not evidence about it.
	try := func(name string, decisive bool, attempts [][]string) {
		var last string
		for _, argv := range attempts {
			full := append([]string{"netns", "exec", synthNetns}, argv...)
			_, err := run(ctx, "ip", full...)
			if err == nil {
				out = append(out, ClientPathProbe{Name: name, OK: true, Decisive: decisive})
				return
			}
			last = trimProbeError(err)
		}
		out = append(out, ClientPathProbe{Name: name, Why: last, Decisive: decisive})
	}

	// The gateway first, and it earns its place by being the discriminator. It
	// proves the tunnel itself — encrypt, cross the client interface, decrypt —
	// without depending on the resolver, the proxy or an exit. When this passes
	// and the others fail, the client leg is fine and something beyond it is not;
	// when this fails, nothing further is worth reading. Working that out by hand
	// took a stand session, which is a good reason for the metric to say it.
	try("icmp/gateway", true, [][]string{{"ping", "-c", "2", "-W", "2", "-q", t.Gateway}})

	// TCP through the tunnel, through mihomo, to an exit and out. Two targets:
	// the same URL the tier prober uses, and a second operator's, so one provider's
	// bad hour cannot spend an attempt of the migration's three.
	var tcpAttempts [][]string
	for _, u := range defaultProbeURLs {
		tcpAttempts = append(tcpAttempts, []string{"curl", "-sS", "-o", "/dev/null", "--max-time", timeout, u})
	}
	try("tcp/443", true, tcpAttempts)

	// UDP through the tunnel, through mihomo's TPROXY path, and BACK. This is the
	// probe the August outage would have failed, and the reason it is not `getent`:
	// getent reads resolv.conf, where the fleet's resolver is the client gateway,
	// so the query never left the tunnel and the probe was green throughout.
	if t.SelfExec != "" {
		var dnsAttempts [][]string
		for _, s := range defaultResolvers {
			dnsAttempts = append(dnsAttempts, []string{"timeout", timeout, t.SelfExec, DNSProbeFlag, s})
		}
		try("udp/53", true, dnsAttempts)
	}

	// Destinations that must NOT be swallowed by the interception. The management
	// address is this host's own, so it answers whenever the path to it is right —
	// which makes it the one exemption we can assert without depending on anybody
	// else being up, and therefore the one that is allowed to revert a move.
	if ip, err := netip.ParseAddr(strings.TrimSpace(t.MgmtAddr)); err == nil {
		try("icmp/mgmt", true, [][]string{{"ping", "-c", "2", "-W", "2", "-q", ip.String()}})
	}
	// The rest of the direct set is probed for the record, not for the decision: an
	// exit can be drained, rebooting or simply refusing ICMP, and none of that is a
	// reason to move every client back.
	if targets := hostAddrs(t.Direct); len(targets) > 0 {
		var attempts [][]string
		for _, ip := range targets {
			attempts = append(attempts, []string{"ping", "-c", "2", "-W", "2", "-q", ip})
		}
		try("icmp/direct", false, attempts)
	}
	return out
}

// hostAddrs keeps the single-host entries of a CIDR list — the exit public IPs
// and pinned hosts that are pingable as written. A network prefix has no address
// worth probing, so it is skipped rather than guessed at.
func hostAddrs(cidrs []string) []string {
	var out []string
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is4() || p.Bits() != 32 {
			continue
		}
		out = append(out, p.Addr().String())
		if len(out) == 2 {
			break // two is a sample; the whole direct list is not an uptime board
		}
	}
	return out
}

// ClientPathOK reports whether the path is healthy enough to keep a migration in
// place. Only DECISIVE probes count, and an empty set is NOT ok: it means nothing
// was measured, and reporting that as healthy is how a prober becomes a source of
// false confidence.
func ClientPathOK(probes []ClientPathProbe) bool {
	decisive := 0
	for _, p := range probes {
		if !p.Decisive {
			continue
		}
		decisive++
		if !p.OK {
			return false
		}
	}
	return decisive > 0
}

// TrimProbeError is trimProbeError for callers outside the package that carry a
// probe's reason into a verdict.
func TrimProbeError(why string) string {
	if why == "" {
		return ""
	}
	return trimProbeError(errors.New(why))
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
