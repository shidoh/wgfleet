package master

import (
	"context"
	"fmt"
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
}

func (netnsPlanner) Component() string { return "mihomo network namespace" }

func (p netnsPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("mihomo network namespace: node has no master spec")
	}
	wanted, _ := spec.Master.NetnsWanted()
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
		nftActions, nerr := p.interceptionActions(ctx, in, spec, run)
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
func (p netnsPlanner) interceptionActions(ctx context.Context, in netns.Input, spec domain.NodeSpec, run netns.Runner) ([]reconcile.Action, error) {
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
	table := fmt.Sprintf("%d", netfw.NetnsRouteTable)
	pref := fmt.Sprintf("%d", netfw.NetnsRulePref)
	return []reconcile.Action{
		file,
		reconcile.ExecAction("load the in-namespace interception",
			"nsenter", "--net="+nsPath, "nft", "-f", path),
		reconcile.BestEffortExecAction("clear any stale rule at the namespace priority",
			"ip", "rule", "del", "pref", pref),
		reconcile.ExecAction("send client traffic to mihomo's namespace",
			"ip", "rule", "add", "iif", p.clientIface(spec), "lookup", table, "pref", pref),
		reconcile.ExecAction("route the namespace table through the veth",
			"ip", "route", "replace", "default", "via", peerIP, "dev", in.HostIface, "table", table),
	}, nil
}

func (p netnsPlanner) clientIface(spec domain.NodeSpec) string {
	if spec.Master != nil && spec.Master.ClientWG != nil {
		return clientIfaceName("")
	}
	return clientIfaceName("")
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
	if wanted, _ := spec.Master.NetnsWanted(); !wanted {
		return fmt.Errorf("disabled by master.client_via_netns")
	}
	return netns.Ready(ctx, netns.Input{
		Holder:     domain.NetnsHolder,
		HostIface:  domain.NetnsHostIface,
		PeerIface:  domain.NetnsPeerIface,
		CIDR:       spec.Master.NetnsLinkCIDR(),
		ClientCIDR: spec.WGServer.AddressPool,
	}, netns.Exec)
}
