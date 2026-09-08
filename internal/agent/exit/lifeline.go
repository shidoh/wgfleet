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
		if _, err := os.Stat(p.confPath); err != nil {
			return []reconcile.Action{reconcile.NoChangeAction(lifelineComponent, "not configured")}, nil
		}
		rm, err := reconcile.RemoveFileAction(p.confPath, "lifeline disabled: remove its config")
		if err != nil {
			return nil, err
		}
		return []reconcile.Action{
			reconcile.BestEffortExecAction(
				"lifeline disabled: bring "+domain.LifelineInterface+" down",
				"awg-quick", "down", p.confPath),
			rm,
			p.clearDeferred(),
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

// deferredPath is where the planner records WHY it is not applying the spec. The
// `lifeline` health check only sees the world (is awgl0 up), and a deferral is a
// decision, not a state of the world: without this the operator's only signal
// would be a line in a plan nobody is reading.
func (p lifelinePlanner) deferredPath() string { return p.confPath + ".deferred" }

// deferred returns the plan for a pass that declines to apply, recording the
// reason where the operator and the status page can find it.
func (p lifelinePlanner) deferred(reason string) []reconcile.Action {
	act, err := reconcile.FileAction(p.deferredPath(), []byte(reason+"\n"), 0o600, nil)
	if err != nil {
		// Recording the reason is diagnostics; failing the pass over it would be the
		// freeze this whole branch exists to avoid.
		return []reconcile.Action{reconcile.NoChangeAction(lifelineComponent, reason)}
	}
	return []reconcile.Action{act, reconcile.NoChangeAction(lifelineComponent, reason)}
}

// clearDeferred removes the marker once the planner is applying or converged.
func (p lifelinePlanner) clearDeferred() reconcile.Action {
	act, err := reconcile.RemoveFileAction(p.deferredPath(), "clear the lifeline deferral")
	if err != nil {
		return reconcile.NoChangeAction(lifelineComponent, "")
	}
	return act
}
