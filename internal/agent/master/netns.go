package master

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netns"
)

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
	if len(steps) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("mihomo network namespace",
			"namespace link already converged")}, nil
	}
	actions := make([]reconcile.Action, 0, len(steps))
	for _, s := range steps {
		actions = append(actions, reconcile.ExecAction(s.Summary, s.Argv...))
	}
	return actions, nil
}
