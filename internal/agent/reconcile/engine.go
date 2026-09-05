package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Planner renders the actions needed to bring one subsystem (WG, nftables,
// routing, ...) to the desired NodeSpec. Plan MUST be side-effect-free: it may
// read current state to compute diffs but must never mutate the node. This is
// what makes dry-run trustworthy.
type Planner interface {
	// Component is the planner's name, shown in plan output.
	Component() string
	// Plan renders the actions for spec without changing anything.
	Plan(ctx context.Context, spec domain.NodeSpec) ([]Action, error)
}

// DependentPlanner is a planner whose plan is only meaningful while another
// component converged.
//
// It exists because the pass no longer stops at the first failure, and that
// exposed a pair that really is one build: the master's NAT renders the "moved"
// ruleset — host interception removed, client traffic routed at the namespace —
// on the strength of a decision the namespace planner is supposed to have carried
// out one step earlier. When the pass aborted, a namespace that failed to arm took
// the NAT with it and the host kept intercepting. Now it does not, so the NAT
// would tear down the host path with nothing on the other side, and clients go
// nowhere until the mover reverts, up to thirty seconds later.
//
// Ordering cannot express that, and neither can a comment. A dependency can.
type DependentPlanner interface {
	// DependsOn names the component this one is only valid after, or "" when it
	// stands on its own — which may depend on the spec, so it is asked every pass.
	DependsOn() string
}

// ScheduledPlanner is an optional interface a Planner may implement to declare
// that its changes are driven by an out-of-band schedule (e.g. a timer-based
// feed refresh), not by divergence from the desired spec. The engine flags such
// plans (Plan.Scheduled) so drift detection excludes their expected changes.
type ScheduledPlanner interface {
	Scheduled() bool
}

// Engine runs an ordered set of planners. Order matters: e.g. firewall before
// the interface comes up, routing after the egress interface exists.
type Engine struct {
	planners []Planner
	log      *slog.Logger
}

// NewEngine builds an engine from planners, run in the given order.
func NewEngine(log *slog.Logger, planners ...Planner) *Engine {
	if log == nil {
		log = slog.Default()
	}
	// A dependency naming a component that is not in this engine — a typo, a
	// renamed component — would be silently inert: the lookup misses, nothing is
	// ever skipped, and the guarantee the caller thinks it has does not exist. Say
	// so at construction, where it is a programming error and not a 3am mystery.
	// A component depending on itself is the same class and deadlocks nothing, but
	// it can never be satisfied, so it is refused too.
	known := map[string]bool{}
	for _, p := range planners {
		known[p.Component()] = true
	}
	for _, p := range planners {
		dep, ok := p.(DependentPlanner)
		if !ok {
			continue
		}
		on := dep.DependsOn()
		switch {
		case on == "":
		case on == p.Component():
			log.Error("planner depends on itself; the dependency is ignored", "component", on)
		case !known[on]:
			log.Error("planner depends on a component this engine does not run; the dependency is ignored",
				"component", p.Component(), "depends_on", on)
		}
	}
	return &Engine{planners: planners, log: log}
}

// Reconcile renders every planner's plan, then — only in ModeApply — executes
// each action. In ModePlan it returns the Report without touching the node, so
// callers can print exactly what would change.
//
// A failing component does NOT stop the pass. It used to: the first error, in
// planning or in applying, returned immediately, and every planner after it was
// skipped. The master runs about twenty planners in a fixed order, so a component
// near the front took down everything behind it — a failure in the namespace
// interception, sixth in that list, left the node with no host NAT, no DOCKER-USER
// accept, no DNS filter and no client VLESS inbound, every thirty seconds, for as
// long as the cause lasted. The blast radius of a fault had nothing to do with
// what the fault was about.
//
// So each component's failure is recorded on its own plan and the pass carries on
// to the components that are unrelated to it. Within a component the remaining
// actions ARE skipped — they are the steps of one build and they depend on each
// other. The pass still ends in an error, so the node reports Degraded and the
// operator sees it; it simply converges everything it can first. Actions already
// applied are not rolled back (reconcile is idempotent, so a re-run converges).
func (e *Engine) Reconcile(ctx context.Context, spec domain.NodeSpec, mode Mode) (Report, error) {
	report := Report{Mode: mode}
	var failed []error
	broken := map[string]bool{}
	for _, p := range e.planners {
		if dep, ok := p.(DependentPlanner); ok {
			if on := dep.DependsOn(); on != "" && broken[on] {
				// Not an error of its own, and not a silent skip either: the plan says
				// which component it is waiting for, and why nothing was changed.
				e.log.Warn("component skipped: what it builds on did not converge",
					"component", p.Component(), "waiting_for", on)
				report.Plans = append(report.Plans, Plan{
					Component: p.Component(),
					Actions: []Action{NoChangeAction(p.Component(),
						"skipped: "+on+" did not converge, and this would act on what it was supposed to build")},
				})
				// A component that was skipped did not converge either, so anything
				// standing on IT is in the same position. Without this the chain stops
				// at one link and a third component acts on a second one that never ran.
				broken[p.Component()] = true
				continue
			}
		}
		actions, err := p.Plan(ctx, spec)
		if err != nil {
			err = fmt.Errorf("plan %s: %w", p.Component(), err)
			e.log.Error("component did not converge", "component", p.Component(), "err", err)
			report.Plans = append(report.Plans, Plan{Component: p.Component(), Err: err})
			failed = append(failed, err)
			broken[p.Component()] = true
			continue
		}
		plan := Plan{Component: p.Component(), Actions: actions}
		if sp, ok := p.(ScheduledPlanner); ok && sp.Scheduled() {
			plan.Scheduled = true
		}

		if mode == ModeApply {
			for _, a := range actions {
				if !a.Changes() {
					continue
				}
				e.log.Info("applying action", "component", p.Component(),
					"kind", a.Kind, "target", a.Target)
				if err := a.run(ctx); err != nil {
					// This component's remaining actions are the rest of one build and
					// depend on the step that just failed; the components after it do not.
					err = fmt.Errorf("apply %s/%s (%s): %w", p.Component(), a.Target, a.Kind, err)
					e.log.Error("component did not converge", "component", p.Component(), "err", err)
					plan.Err = err
					failed = append(failed, err)
					broken[p.Component()] = true
					break
				}
			}
		}
		report.Plans = append(report.Plans, plan)
	}
	if len(failed) > 0 {
		return report, errors.Join(failed...)
	}
	return report, nil
}
