package exit

import (
	"context"
	"os"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/wgiface"
	"github.com/shidoh/wgfleet/internal/awgmod"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// --- lifeline interface (the reserve client leg an exit carries) ---
//
// The exit mirror of the master's clientWGPlanner: same render, same compare,
// same "patch the peers rather than bounce the device" decision tree — run
// through the shared wgiface helpers so the two interfaces cannot drift apart in
// their answers. Two things differ, and both are simplifications:
//
//   - No claim file. The master may INHERIT its client leg from wg-easy, so it
//     needs a written record that it was the one that raised it. Nothing but this
//     agent ever creates awgl0, so the rendered config's presence is already the
//     only ownership evidence the disable path needs.
//   - No wg-easy retirement and no backend gymnastics. Exits carry the AmneziaWG
//     kernel module by construction — it is what their own WGServer runs on.

// lifelineComponent is the planner's name in plan output and in the journal.
const lifelineComponent = "lifeline interface"

// lifelinePlanner renders and raises the exit's lifeline interface.
type lifelinePlanner struct {
	confPath   string                 // awg-quick config for domain.LifelineInterface
	privateKey string                 // the exit's lifeline private key (node-local)
	up         func(name string) bool // nil ⇒ real `ip link` probe
	awgGen     func() (int, error)    // nil ⇒ real modinfo probe (tests inject)
	// ifacePeers lists the live interface's peer public keys. nil ⇒ real `awg show`.
	ifacePeers func(name string) ([]string, error)
}

func (lifelinePlanner) Component() string { return lifelineComponent }

func (p lifelinePlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	ls := spec.Lifeline
	if ls == nil {
		// No lifeline in the spec: either this exit never had one (the common case —
		// the knob is per-exit and off by default) or the operator just cleared it.
		// The rendered config tells the two apart, and it can, because nothing else on
		// the node writes that file or raises that interface.
		//
		// Disabling therefore converges in TWO passes, and the order is load-bearing.
		// The config is what `awg-quick down` READS to find the interface, and the
		// down is best-effort: removing both in one pass means a down that failed
		// leaves awgl0 up with nothing left to take it down — and with the spec gone,
		// the `lifeline` health check is gone too, so an orphaned interface still
		// carrying live client peers reports as "not configured" forever.
		_, statErr := os.Stat(p.confPath)
		confPresent := statErr == nil
		switch {
		case confPresent && p.isUp():
			// Down only. The config stays until a pass sees the interface actually gone.
			return []reconcile.Action{reconcile.BestEffortExecAction(
				"lifeline disabled: bring "+domain.LifelineInterface+" down (its config is kept until it is)",
				"awg-quick", "down", p.confPath)}, nil
		case confPresent:
			rm, err := reconcile.RemoveFileAction(p.confPath, "lifeline disabled: remove its config")
			if err != nil {
				return nil, err
			}
			return []reconcile.Action{rm, p.clearDeferred()}, nil
		case p.isUp():
			// An interface with no config: /etc wiped, a half-finished restore, or the
			// removal above running against a down that had silently failed earlier.
			// `awg-quick down` has nothing to read, so delete the device directly.
			return []reconcile.Action{reconcile.BestEffortExecAction(
				"lifeline disabled: delete the orphaned "+domain.LifelineInterface+" (no config to bring it down with)",
				"ip", "link", "del", domain.LifelineInterface)}, nil
		}
		// Neither a config nor an interface: nothing to do, and nothing to remember.
		return []reconcile.Action{
			p.clearDeferred(),
			reconcile.NoChangeAction(lifelineComponent, "not configured"),
		}, nil
	}
	if p.privateKey == "" {
		// Same gate as the master's client leg: without the key we would render an
		// interface nobody can authenticate against. Defer rather than fail the pass.
		return p.deferred("pending: lifeline private key not yet available"), nil
	}
	if err := ls.ClientWGSpec.Validate(); err != nil {
		// Never fail the pass. This planner runs before WARP, routing, DNS and the
		// reality inbound, and the engine stops at the first planner error — so one
		// malformed reserve spec would freeze the exit's PRIMARY data plane. The
		// last-good lifeline config stays on disk and keeps serving; the reason is
		// recorded next to it.
		return p.deferred("spec rejected, keeping the last-good config: " + err.Error()), nil
	}
	// AmneziaWG 3.x needs a 3.x kernel module: its netlink attribute layout is not
	// the 1.x one, so `awg setconf` would reject the config and awg-quick would
	// leave the interface down. Check BEFORE rendering — writing a config we know
	// cannot be applied and then running awg-quick takes the live lifeline down,
	// which is exactly the interface people are on when the master is unreachable.
	if ls.AWG != nil && ls.AWG.AWG3Enabled() {
		if err := awgmod.CheckAWG3Supported(p.awgGen); err != nil {
			return p.deferred("AmneziaWG 3.x refused, keeping the last-good config: " + err.Error()), nil
		}
	}

	cfg, err := wg.RenderClientInterface(wg.ClientInterfaceInput{Spec: ls.ClientWGSpec, PrivateKey: p.privateKey})
	if err != nil {
		return nil, err
	}
	prevRaw, _ := os.ReadFile(p.confPath)
	prevCfg := string(prevRaw)
	file, err := reconcile.FileAction(p.confPath, []byte(cfg), 0o600, wg.RedactConfig)
	if err != nil {
		return nil, err
	}
	// Past every deferral: whatever the last pass declined to do, it is doing now.
	actions := []reconcile.Action{file, p.clearDeferred()}

	name := wgiface.Name(p.confPath)
	peersMatch, _ := wgiface.ServesPeers(name, ls.Clients, p.ifacePeers)
	// Before deciding to recreate the device: can this be done as a peer edit?
	// `awg-quick down` + `up` destroys the interface and every session on it. That
	// is a fair price for an interface-level change and a bad one for adding a
	// credential — worse here than on the master, because the people on the lifeline
	// are on it precisely because their normal path is already gone.
	if (file.Changes() || !peersMatch) && p.isUp() {
		if delta := wgiface.PeerDelta(name, ls.Clients, prevCfg, cfg, p.ifacePeers); delta != nil {
			return append(actions, delta...), nil
		}
	}
	backend := ls.ResolvedBackend()
	switch {
	case file.Changes():
		return append(actions, p.applyActions(backend, "config changed")...), nil
	case !p.isUp():
		return append(actions, p.applyActions(backend, "interface was down")...), nil
	case !peersMatch:
		return append(actions, p.applyActions(backend, "live peers do not match the spec")...), nil
	}
	return append(actions, reconcile.NoChangeAction(lifelineComponent, "interface already up")), nil
}

// applyActions brings the interface to the rendered config. BOTH steps are
// best-effort on purpose: this planner runs ahead of the WARP egress, policy
// routing, the DNS filter and the reality inbound, and the reconcile engine stops
// the whole pass at the first failed action. A reserve interface that will not
// come up must not take the exit's primary data plane with it. The failure is
// visible as a warning and as the `lifeline` health check going red, and the next
// pass retries.
func (p lifelinePlanner) applyActions(backend domain.ClientWGBackend, why string) []reconcile.Action {
	return []reconcile.Action{
		wgiface.QuickAction(backend, "down", p.confPath, true, "bring the lifeline interface down (if up): "+why),
		wgiface.QuickAction(backend, "up", p.confPath, true, "bring the lifeline interface up: "+why),
	}
}

func (p lifelinePlanner) isUp() bool {
	name := wgiface.Name(p.confPath)
	if p.up == nil {
		return wgiface.IsUp(name)
	}
	return p.up(name)
}

// deferral is where the planner records WHY it is not applying the spec, and the
// `lifeline` health check reads the same file: the check otherwise only sees the
// world (is awgl0 up), and a deferral is a decision, not a state of the world.
func (p lifelinePlanner) deferral() wgiface.Deferral {
	return wgiface.Deferral{Path: wgiface.DeferredPath(p.confPath), Component: lifelineComponent}
}

func (p lifelinePlanner) deferred(reason string) []reconcile.Action {
	return p.deferral().Write(reason)
}

func (p lifelinePlanner) clearDeferred() reconcile.Action { return p.deferral().Clear() }
