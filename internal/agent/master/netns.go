package master

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	}

	if len(actions) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo network namespace",
			"namespace link already converged")}, nil
	}
	return actions, nil
}

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
	ruleset, err := netfw.RenderNetnsNAT(netfw.NetnsNATInput{
		PeerIface:  in.PeerIface,
		RedirAddr:  fmt.Sprintf("%s:%d", peerIP, redir),
		TProxyAddr: fmt.Sprintf("%s:%d", peerIP, mihomo.TProxyPortFor(redir)),
	})
	if err != nil {
		return nil, err
	}
	path := p.nftPath
	if path == "" {
		path = netnsNFTPath
	}
	file, ferr := reconcile.FileAction(path, []byte(ruleset), 0o644, nil)
	if ferr != nil {
		return nil, ferr
	}
	if p.clientIface == "" {
		// No interface, no rule. Installing one with an empty or invented `iif` is
		// worse than installing none: it applies cleanly, matches nothing, and the
		// host has already been told to stop intercepting.
		return nil, fmt.Errorf("mihomo network namespace: client interface is unknown")
	}
	table := fmt.Sprintf("%d", netfw.NetnsRouteTable)
	pref := fmt.Sprintf("%d", netfw.NetnsRulePref)
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
	return []reconcile.Action{
		file,
		reconcile.ExecAction("load the in-namespace interception",
			"nsenter", "--net="+nsPath, "nft", "-f", path),
		reconcile.BestEffortExecAction("clear any stale rule at the namespace priority",
			"ip", "rule", "del", "pref", pref),
		reconcile.ExecAction(summary, rule...),
		reconcile.ExecAction("route the namespace table through the veth",
			"ip", "route", "replace", "default", "via", peerIP, "dev", in.HostIface, "table", table),
	}, nil
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
	host, port := exitProbeTarget(spec)
	return netns.Ready(ctx, netns.Input{
		Holder:     domain.NetnsHolder,
		HostIface:  domain.NetnsHostIface,
		PeerIface:  domain.NetnsPeerIface,
		CIDR:       spec.Master.NetnsLinkCIDR(),
		ClientCIDR: spec.WGServer.AddressPool,
		ProbeHost:  host,
		ProbePort:  port,
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
// Only literal addresses are used. A hostname would need the namespace's resolver
// to answer before the probe can run, which makes a reachability check depend on
// the thing it is meant to be independent of; and netns.Ready refuses anything
// that is not an address anyway, because the target is formatted into a bash word.
func exitProbeTarget(spec domain.NodeSpec) (string, int) {
	if spec.Master == nil {
		return "", 0
	}
	for _, t := range spec.Master.ExitTunnels {
		if t.Drained || t.Endpoint == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(t.Endpoint)
		if err != nil {
			continue
		}
		addr, aerr := netip.ParseAddr(host)
		if aerr != nil {
			continue
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil || port < 1 || port > 65535 {
			continue
		}
		return addr.String(), port
	}
	return "", 0
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
