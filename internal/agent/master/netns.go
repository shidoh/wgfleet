package master

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/netns"
)

// netnsNFTPath is where the in-namespace ruleset is written on a real node.
const netnsNFTPath = "/etc/wgfleet/wgfleet-netns.nft"

// netnsPlanner converges the network namespace mihomo runs in: the veth to the
// holder container, both addresses, and the two routes that make the namespace
// reachable in each direction.
//
// It changes nothing about where client traffic goes. The namespace is inert
// until the interception rules move into it, which is a separate decision made
// later in the pass — so this planner can run on a live master, be inspected, and
// be wrong, without a client noticing. That separation is the point: the risky
// half of this migration is one routing rule, and everything else can be built
// and verified first.
type netnsPlanner struct {
	// run executes one command; nil ⇒ netns.Exec. Injected in tests.
	run netns.Runner
	// attached reports whether client interception should live in the namespace
	// yet. nil ⇒ never: the plumbing is built and left inert.
	attached func() bool
	// nftPath is where the in-namespace ruleset is written; "" ⇒ the canonical path.
	nftPath string
	// composePath is the master's compose file, needed to recreate mihomo when it
	// has been left behind in a namespace the holder no longer owns.
	composePath string
	// nftCheck validates a ruleset before it is written; nil ⇒ the real `nft -c`.
	// A parameter rather than a package variable for the reason the host's copy
	// became one: a package-level hook is a data race the first time two tests run
	// in parallel, and `go vet` cannot see it.
	nftCheck func([]byte) error
	// clientIface is the interface client traffic arrives on — the `iif` the
	// routing rule matches. Passed in like every other planner's copy of it rather
	// than derived here: an earlier version derived it from an empty path and got
	// ".", a name no interface has, so the rule installed cleanly and matched
	// nothing. The host had already stopped intercepting by then, which is the
	// outage this whole change exists to prevent.
	clientIface string
}

func (netnsPlanner) Component() string { return "mihomo network namespace" }

func (p netnsPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo network namespace: node has no master spec")
	}
	wanted, canary, werr := spec.Master.NetnsWanted()
	if werr != nil {
		// A value we do not understand is a refusal, not a guess. Reported rather than
		// swallowed: an operator who mistyped the knob has to learn it from the plan,
		// not from the traffic.
		return nil, fmt.Errorf("mihomo network namespace: %w", werr)
	}
	if !wanted {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo network namespace",
			"disabled by master.client_via_netns; mihomo stays on host networking")}, nil
	}
	if spec.WGServer.AddressPool == "" {
		// Without the client pool there is no return route to render, and a namespace
		// whose replies cannot reach clients is worse than none.
		return []reconcile.Action{reconcile.NoChangeAction("mihomo network namespace",
			"pending: client pool unknown")}, nil
	}

	run := p.run
	if run == nil {
		run = netns.Exec
	}
	in := netns.Input{
		Holder:     domain.NetnsHolder,
		HostIface:  domain.NetnsHostIface,
		PeerIface:  domain.NetnsPeerIface,
		CIDR:       spec.Master.NetnsLinkCIDR(),
		ClientCIDR: spec.WGServer.AddressPool,
		MTU:        netnsLinkMTU(spec),
	}

	steps, err := netns.Plan(ctx, in, run)
	if err != nil {
		// The holder is not up yet — normally because the compose planner created it
		// earlier in this same pass and Docker has not started it. DEFER rather than
		// fail: this planner runs ahead of the master NAT and mihomo, and failing here
		// would stop the node converging anything at all over a container that is a
		// second away from existing.
		return []reconcile.Action{reconcile.NoChangeAction("mihomo network namespace",
			"pending: "+err.Error())}, nil
	}
	actions := make([]reconcile.Action, 0, len(steps)+4)
	for _, s := range steps {
		actions = append(actions, reconcile.ExecAction(s.Summary, s.Argv...))
	}

	// The interception itself, and the routing that feeds it. Both only once the
	// agent has decided the namespace is fit to carry traffic — see netnsMover.
	// Until then the plumbing above sits there doing nothing, which is exactly what
	// makes it safe to build on a live master.
	if p.attached != nil && p.attached() {
		nftActions, nerr := p.interceptionActions(ctx, in, spec, canary, run)
		if nerr != nil {
			return nil, nerr
		}
		actions = append(actions, nftActions...)
	} else {
		// The way back. Not "add nothing": the rules installed by a previous pass are
		// still in the kernel, and the one at priority 400 sorts ahead of the TPROXY
		// mark rule the host has just re-armed — so leaving it there sends every
		// intercepted client packet into a namespace nothing is listening in.
		actions = append(actions, p.detachActions(ctx, run)...)
	}

	if len(actions) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo network namespace",
			"namespace link already converged")}, nil
	}
	return actions, nil
}

// netnsDirectRulePref is the ip-rule priority that keeps destination-based
// exemptions OUT of the namespace. Lower than NetnsRulePref so it is consulted
// first: `ip rule` is evaluated in ascending priority order, and the whole point
// is to answer "is this one of the destinations that must not be intercepted"
// before "is this client traffic".
const netnsDirectRulePref = 390

// interceptionActions renders the in-namespace ruleset and the host-side policy
// routing that sends client traffic into it.
//
// The routing rule carries an EXPLICIT priority. The master's one existing rule
// was added without one and landed at 32765 by accident of insertion order; a
// second unnumbered rule would land at 32764 and the relative order of the two
// would then depend on which was added first, which changes across a re-apply.
// The exits have used fixed priorities per logical rule from the start.
func (p netnsPlanner) interceptionActions(ctx context.Context, in netns.Input, spec domain.NodeSpec, canary string, run netns.Runner) ([]reconcile.Action, error) {
	nsPath, err := netns.Path(ctx, in.Holder, run)
	if err != nil {
		return nil, nil // the holder went away; the next pass will rebuild
	}
	_, peerAddr, err := netns.LinkAddrs(in.CIDR)
	if err != nil {
		return nil, err
	}
	peerIP, _, _ := strings.Cut(peerAddr, "/")
	redir := spec.Master.RedirPort
	if redir == 0 {
		redir = mihomo.DefaultRedirPort
	}
	direct := directDestinations(spec)
	ruleset, err := netfw.RenderNetnsNAT(netfw.NetnsNATInput{
		PeerIface:   in.PeerIface,
		RedirAddr:   fmt.Sprintf("%s:%d", peerIP, redir),
		TProxyAddr:  fmt.Sprintf("%s:%d", peerIP, mihomo.TProxyPortFor(redir)),
		ClientCIDR:  in.ClientCIDR,
		DirectCIDRs: direct,
	})
	if err != nil {
		return nil, err
	}
	path := p.nftPath
	if path == "" {
		path = netnsNFTPath
	}
	if p.clientIface == "" {
		// No interface, no rule. Installing one with an empty or invented `iif` is
		// worse than installing none: it applies cleanly, matches nothing, and the
		// host has already been told to stop intercepting.
		return nil, fmt.Errorf("mihomo network namespace: client interface is unknown")
	}
	// Through NFTApply, with an nsenter'd nft. Everything that machinery gives the
	// host's rulesets — a pre-check before the bytes are written, an applied marker
	// so a FAILED apply is not recorded as done, the previous ruleset kept as a way
	// back, a re-apply when the kernel has lost the table — is worth more here, not
	// less: nobody notices a missing table inside a namespace.
	nsNFT := []string{"nsenter", "--net=" + nsPath, "nft"}
	actions, err := reconcile.NFTApplyWith(nsNFT, path, []byte(ruleset),
		func() bool { return p.nsTableLoaded(ctx, nsPath, run) }, p.nftCheck,
		"apply the in-namespace interception atomically")
	if err != nil {
		return nil, err
	}

	table := fmt.Sprintf("%d", netfw.NetnsRouteTable)
	pref := fmt.Sprintf("%d", netfw.NetnsRulePref)

	// Destination exemptions FIRST, and they are the difference between a migration
	// and an outage.
	//
	// `ip rule … iif wg0 lookup 51822` takes the whole client interface, and table
	// 51822 holds one default route into the namespace. Every destination that is
	// supposed to stay off the proxy goes with it: the corporate networks clients
	// carry in route_through_cidrs, the management overlay, the exits' own public
	// addresses, client-to-client traffic inside the pool. Today those
	// live as `ip daddr !=` guards in the host ruleset, which the move deletes.
	//
	// A lower priority is the whole mechanism: rules are consulted in ascending
	// order, so "is this an exempt destination" is asked before "is this a client".
	// The in-namespace guards are the second line, for anything that reaches it
	// anyway.
	live := livePrefixes(ctx, run, netnsDirectRulePref)
	want := map[string]bool{}
	for _, cidr := range direct {
		want[cidr] = true
		if live[cidr] {
			continue
		}
		actions = append(actions, reconcile.ExecAction(
			"keep "+cidr+" out of the namespace (direct destination)",
			"ip", "rule", "add", "to", cidr, "lookup", "main", "pref", fmt.Sprintf("%d", netnsDirectRulePref)))
	}
	// And withdraw the ones that are no longer exempt. Without this an operator who
	// removes a direct CIDR from the manifest leaves the rule behind forever, and
	// that destination silently keeps bypassing the proxy.
	for cidr := range live {
		if want[cidr] {
			continue
		}
		actions = append(actions, reconcile.BestEffortExecAction(
			"stop exempting "+cidr+" (no longer a direct destination)",
			"ip", "rule", "del", "to", cidr, "lookup", "main", "pref", fmt.Sprintf("%d", netnsDirectRulePref)))
	}

	// The rule that actually moves traffic. With a canary it is scoped to those
	// client sources and everyone else stays on the host path — which is what makes
	// the blast radius of this migration one device instead of every client. The
	// mode was documented, returned by NetnsWanted and then discarded at every call
	// site: an operator who set a /32 got the full move.
	rule := []string{"ip", "rule", "add"}
	summary := "send client traffic to mihomo's namespace"
	if canary != "" {
		rule = append(rule, "from", canary)
		summary = "send client traffic from " + canary + " to mihomo's namespace (canary)"
	}
	rule = append(rule, "iif", p.clientIface, "lookup", table, "pref", pref)

	// Gated on what the kernel actually has. These used to be bare execs: every pass
	// deleted the rule and added it back, and between the two calls a client packet
	// takes the main table, leaves by the master's uplink and is masqueraded — the
	// precise leak the fail-closed drop exists to prevent, opened twice a minute by
	// the code that installs it. It also made every report show changes forever.
	if !p.routingLive(ctx, run, pref, table, peerIP, in.HostIface, canary) {
		actions = append(actions,
			reconcile.BestEffortExecAction("clear any stale rule at the namespace priority",
				"ip", "rule", "del", "pref", pref),
			reconcile.ExecAction(summary, rule...),
			reconcile.ExecAction("route the namespace table through the veth",
				"ip", "route", "replace", "default", "via", peerIP, "dev", in.HostIface, "table", table))
	} else {
		actions = append(actions, reconcile.NoChangeAction("namespace routing",
			"client traffic already routed into the namespace"))
	}

	// mihomo in the RIGHT namespace, not merely in one.
	//
	// `network_mode: container:X` is resolved when the container is created, so a
	// holder that restarts — an OOM kill, a `docker restart`, a daemon reload —
	// comes back with a NEW namespace while mihomo stays in the old one. The old
	// namespace has no veth (it died with the holder's last interface) and holds no
	// ruleset, so mihomo is alive, healthy by every container check, and reachable
	// by nothing. `depends_on` does not help: it orders startup, not restarts.
	if !p.mihomoIsInTheNamespace(ctx, nsPath, run) {
		actions = append(actions, reconcile.ExecAction(
			"put mihomo back in the holder's namespace (the holder restarted without it)",
			"docker", "compose", "-f", p.composePath, "up", "-d", "--force-recreate", "mihomo"))
	}

	// TPROXY's other half, inside the namespace. `tproxy` only assigns the socket;
	// the routing decision happens AFTER prerouting, and without a policy route for
	// the mark the kernel looks at a destination that still belongs to somebody else
	// and sends the packet out the default route. The transparent socket never sees
	// a datagram.
	//
	// The host has carried this pair since TPROXY was introduced there
	// (tproxyRouteActions); the namespace got the nft rule and not the routing, so
	// the interception would have assigned sockets nothing ever delivered to.
	if !p.nsTProxyRoutingLive(ctx, nsPath, run) {
		nsPrefix := []string{"nsenter", "--net=" + nsPath, "ip"}
		mark := fmt.Sprintf("%#x", netfw.TProxyMark)
		tproxyTable := fmt.Sprintf("%d", netfw.TProxyTable)
		actions = append(actions,
			reconcile.BestEffortExecAction("drop any stale tproxy rule inside the namespace",
				append(append([]string(nil), nsPrefix...), "rule", "del", "fwmark", mark, "lookup", tproxyTable)...),
			reconcile.ExecAction("keep tproxy-marked packets in the namespace",
				append(append([]string(nil), nsPrefix...), "rule", "add", "fwmark", mark, "lookup", tproxyTable)...),
			reconcile.ExecAction("deliver tproxy-marked packets to the local socket",
				append(append([]string(nil), nsPrefix...), "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyTable)...))
	}
	return actions, nil
}

// detachActions undoes everything interceptionActions installed on the HOST.
//
// Symmetry here is not tidiness. `ip rule pref 400` sorts ahead of the TPROXY
// mark rule at 32765, so a rule left behind after mihomo has moved back sends
// every marked client packet into a namespace that is empty or gone — and it also
// swallows every destination the direct-exemption rules were protecting. The
// original branch simply stopped ADDING actions when the decision flipped back,
// which meant the automatic revert — the thing that made "on by default"
// defensible — left clients worse off than the move did, until a human logged in.
func (p netnsPlanner) detachActions(ctx context.Context, run netns.Runner) []reconcile.Action {
	pref := fmt.Sprintf("%d", netfw.NetnsRulePref)
	table := fmt.Sprintf("%d", netfw.NetnsRouteTable)
	var actions []reconcile.Action

	// The ruleset INSIDE the namespace goes first, and leaving it behind is the
	// worst of the leftovers rather than the most obscure.
	//
	// Its UDP interception is fail-closed: `tproxy` finds no transparent socket
	// once mihomo has moved back out, and the next rule drops the datagram. So a
	// namespace that is no longer carrying client traffic silently eats every UDP
	// packet of its OWN — including the DNS query the readiness gate makes before
	// the next attempt. Measured on the stand 2026-09-05: 38 dropped datagrams, the
	// gate failing on DNS, and a node that could never move again because its last
	// revert had broken the check that would have let it.
	if nsPath, err := netns.Path(ctx, domain.NetnsHolder, run); err == nil {
		if _, lerr := run(ctx, "nsenter", "--net="+nsPath, "nft", "list", "table", "ip", netfw.NetnsNATTable); lerr == nil {
			actions = append(actions, reconcile.ExecAction(
				"remove the interception from mihomo's namespace",
				"nsenter", "--net="+nsPath, "nft", "delete", "table", "ip", netfw.NetnsNATTable))
		}
	}
	// And the record that it was applied, so the next attach re-applies from scratch
	// rather than believing a table that is no longer there.
	path := p.nftPath
	if path == "" {
		path = netnsNFTPath
	}
	if forget, ferr := reconcile.RemoveFileAction(reconcile.NFTAppliedMarker(path),
		"forget the applied in-namespace ruleset"); ferr == nil {
		actions = append(actions, forget)
	}
	if p.ruleLive(ctx, run, pref) {
		actions = append(actions, reconcile.ExecAction(
			"stop routing client traffic into the namespace",
			"ip", "rule", "del", "pref", pref))
	}
	for cidr := range livePrefixes(ctx, run, netnsDirectRulePref) {
		actions = append(actions, reconcile.BestEffortExecAction(
			"withdraw the direct-destination exemption for "+cidr,
			"ip", "rule", "del", "to", cidr, "lookup", "main", "pref",
			fmt.Sprintf("%d", netnsDirectRulePref)))
	}
	if out, err := run(ctx, "ip", "route", "show", "table", table); err == nil && strings.TrimSpace(out) != "" {
		actions = append(actions, reconcile.BestEffortExecAction(
			"empty the namespace routing table",
			"ip", "route", "flush", "table", table))
	}
	return actions
}

// directDestinations is what must not be intercepted. The client pool itself is
// included: client-to-client traffic is delivered by the master's own interface
// and has no business crossing a proxy.
func directDestinations(spec domain.NodeSpec) []string {
	var out []string
	seen := map[string]bool{}
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	if spec.Master != nil {
		for _, c := range spec.Master.DirectCIDRs {
			add(c)
		}
	}
	add(spec.WGServer.AddressPool)
	return out
}

// livePrefixes reads the destinations currently exempted at a given ip-rule
// priority. Reading the kernel rather than remembering what we wrote is what lets
// a withdrawn CIDR actually be withdrawn — a planner is rebuilt every pass and
// remembers nothing.
func livePrefixes(ctx context.Context, run netns.Runner, pref int) map[string]bool {
	out := map[string]bool{}
	text, err := run(ctx, "ip", "rule", "list")
	if err != nil {
		return out
	}
	want := fmt.Sprintf("%d:", pref)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != want {
			continue
		}
		for i, f := range fields {
			if f == "to" && i+1 < len(fields) {
				out[fields[i+1]] = true
			}
		}
	}
	return out
}

// ruleLive reports whether any rule sits at a priority.
func (p netnsPlanner) ruleLive(ctx context.Context, run netns.Runner, pref string) bool {
	text, err := run(ctx, "ip", "rule", "list")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), pref+":") {
			return true
		}
	}
	return false
}

// routingLive reports whether the kernel already carries BOTH halves of the move:
// the rule at our priority naming the client interface and the right table, and
// that table's default route through the veth.
func (p netnsPlanner) routingLive(ctx context.Context, run netns.Runner, pref, table, peerIP, hostIface, canary string) bool {
	text, err := run(ctx, "ip", "rule", "list")
	if err != nil {
		return false
	}
	// The SOURCE scope is part of the comparison, not decoration.
	//
	// `ip rule list` prints the canary rule as `from 10.80.0.7 iif wg0 lookup 51822`
	// and the full-move rule as `from all iif wg0 lookup 51822`. A gate that looked
	// only for the interface and the table saw both as the same rule, so widening a
	// canary to `auto` — the last step of every rollout — changed nothing at all and
	// said nothing about it. Measured on the stand 2026-09-05.
	//
	// The kernel drops a /32's prefix length in this output, so the comparison is
	// against the address rather than the prefix as written.
	wantFrom := "from all"
	if canary != "" {
		addr, _, _ := strings.Cut(canary, "/")
		wantFrom = "from " + addr
	}
	found := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, pref+":") {
			continue
		}
		if strings.Contains(line, wantFrom) &&
			strings.Contains(line, "iif "+p.clientIface) &&
			strings.Contains(line, "lookup "+table) {
			found = true
		}
	}
	if !found {
		return false
	}
	route, err := run(ctx, "ip", "route", "show", "table", table)
	if err != nil {
		return false
	}
	return strings.Contains(route, "default via "+peerIP) && strings.Contains(route, "dev "+hostIface)
}

// nsTableLoaded reports whether the namespace holds the interception table.
func (p netnsPlanner) nsTableLoaded(ctx context.Context, nsPath string, run netns.Runner) bool {
	_, err := run(ctx, "nsenter", "--net="+nsPath, "nft", "list", "table", "ip", netfw.NetnsNATTable)
	return err == nil
}

// nsTProxyRoutingLive reports whether the namespace carries the fwmark rule and
// the local default route TPROXY needs.
func (p netnsPlanner) nsTProxyRoutingLive(ctx context.Context, nsPath string, run netns.Runner) bool {
	mark := fmt.Sprintf("%#x", netfw.TProxyMark)
	table := fmt.Sprintf("%d", netfw.TProxyTable)
	rules, err := run(ctx, "nsenter", "--net="+nsPath, "ip", "rule", "list")
	if err != nil || !strings.Contains(rules, "lookup "+table) {
		return false
	}
	// `ip rule list` prints the mark as `fwmark 0x2`; accept either spelling so a
	// kernel that renders it differently does not cause a re-add every pass.
	if !strings.Contains(rules, mark) && !strings.Contains(rules, "fwmark 2") {
		return false
	}
	route, err := run(ctx, "nsenter", "--net="+nsPath, "ip", "route", "show", "table", table)
	return err == nil && strings.Contains(route, "local default")
}

// NamespaceReady reports whether mihomo's namespace is fit to carry client
// traffic: it exists, it can resolve DNS, and it can open a connection outward.
//
// This is the precondition for moving interception into it, and it is checked
// against the namespace itself rather than against anything the controller said.
// A namespace that cannot resolve is the specific trap this guards: mihomo's
// resolver points at 127.0.0.1, which inside its own namespace is its own
// loopback with nothing on it, so a move without this check would take every
// client's DNS down and look, from the outside, like a working migration.
func NamespaceReady(ctx context.Context, spec domain.NodeSpec) error {
	if spec.Master == nil {
		return fmt.Errorf("no master spec")
	}
	if wanted, _, err := spec.Master.NetnsWanted(); err != nil {
		return err
	} else if !wanted {
		return fmt.Errorf("disabled by master.client_via_netns")
	}
	host := exitProbeTarget(spec)
	resolver, bin := "", ""
	if rs := mihomoResolvers(spec, true); len(rs) > 0 {
		resolver = net.JoinHostPort(rs[0], "53")
	}
	if self, err := os.Executable(); err == nil {
		bin = self
	}
	return netns.Ready(ctx, netns.Input{
		Holder:        domain.NetnsHolder,
		HostIface:     domain.NetnsHostIface,
		PeerIface:     domain.NetnsPeerIface,
		CIDR:          spec.Master.NetnsLinkCIDR(),
		ClientCIDR:    spec.WGServer.AddressPool,
		ProbeHost:     host,
		ProbeResolver: resolver,
		ProbeBin:      bin,
	}, netns.Exec)
}

// exitProbeTarget picks an exit endpoint the namespace can dial to prove it has a
// path to the wire, not merely a route table that says it does.
//
// It was the missing half of the readiness gate: netns.Ready has carried this
// check since it was written, validated the address against injection, and was
// never once called with a target — so "ready" meant "DNS resolves", and DNS
// resolves through the HOST namespace, which this migration does not touch. The
// gate could pass on a namespace with no path out at all.
//
// The PORT is deliberately dropped: the endpoint is a WireGuard listener, so it
// is UDP, and the check that used it opened a TCP connection that could only ever
// time out. What is asked instead is whether a packet from the namespace reaches
// the far node at all.
//
// Only literal addresses are used. A hostname would need the namespace's resolver
// to answer before the probe can run, which makes a reachability check depend on
// the thing it is meant to be independent of.
func exitProbeTarget(spec domain.NodeSpec) string {
	if spec.Master == nil {
		return ""
	}
	for _, t := range spec.Master.ExitTunnels {
		if t.Drained || t.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(t.Endpoint)
		if err != nil {
			continue
		}
		addr, aerr := netip.ParseAddr(host)
		if aerr != nil {
			continue
		}
		return addr.String()
	}
	return ""
}

// NetnsPeerIP is mihomo's address inside its namespace — the veth's far end.
// Empty when the interception has not moved, which every caller reads as "mihomo
// is on host networking".
//
// One function, because four places need the same answer and each one deriving it
// from the link CIDR by hand is how they come to disagree: the ruleset would
// point at one address, mihomo would bind another, and the difference is every
// client's traffic.
func NetnsPeerIP(spec domain.NodeSpec, attached bool) string {
	if !attached || spec.Master == nil {
		return ""
	}
	_, peer, err := netns.LinkAddrs(spec.Master.NetnsLinkCIDR())
	if err != nil {
		return ""
	}
	ip, _, _ := strings.Cut(peer, "/")
	return ip
}

// NetnsHostIP is the host end of the same link: what the namespace routes through
// and what mihomo's replies come back over.
func NetnsHostIP(spec domain.NodeSpec) string {
	if spec.Master == nil {
		return ""
	}
	host, _, err := netns.LinkAddrs(spec.Master.NetnsLinkCIDR())
	if err != nil {
		return ""
	}
	ip, _, _ := strings.Cut(host, "/")
	return ip
}

// netnsLinkMTU is what both ends of the veth are set to.
//
// The client interface's own MTU, because that is the size of the packets this
// link will carry: a client datagram arrives on wg0 already fragmented to fit the
// tunnel, is routed across the veth, and leaves again over another tunnel. A veth
// left at the default 1500 claims it can carry more than either neighbour can,
// and the leg it now carries changed character with the move — mihomo-to-exit
// used to be a locally originated connection, where the kernel knows the path
// MTU, and is a FORWARDED one afterwards, where correctness rests on ICMP
// fragmentation-needed coming back. an earlier finding and #18 are both about paths where
// that did not hold.
//
// 0 when the client interface has no MTU of its own: better to leave the kernel
// default than to invent a number.
func netnsLinkMTU(spec domain.NodeSpec) int {
	if spec.Master == nil || spec.Master.ClientWG == nil {
		return 0
	}
	return spec.Master.ClientWG.MTU
}

// mihomoIsInTheNamespace compares the network namespace mihomo is in with the
// holder's. Read from /proc rather than from Docker's own view: `docker inspect`
// reports the network mode that was ASKED for, which is exactly what stays true
// while the namespace behind it goes away.
//
// Unknown counts as correct. A mihomo that is not running, or a /proc we cannot
// read, is not evidence that it is in the wrong place, and recreating a container
// on a guess costs every client connection it holds.
func (p netnsPlanner) mihomoIsInTheNamespace(ctx context.Context, nsPath string, run netns.Runner) bool {
	if p.composePath == "" {
		return true // nothing to recreate it with; do not render an action we cannot take
	}
	out, err := run(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", "mihomo")
	if err != nil {
		return true
	}
	pid := strings.TrimSpace(out)
	if pid == "" || pid == "0" {
		return true // not running: compose will start it, in the right place
	}
	mine, err := run(ctx, "readlink", "/proc/"+pid+"/ns/net")
	if err != nil {
		return true
	}
	theirs, err := run(ctx, "readlink", nsPath)
	if err != nil {
		return true
	}
	return strings.TrimSpace(mine) == strings.TrimSpace(theirs)
}
