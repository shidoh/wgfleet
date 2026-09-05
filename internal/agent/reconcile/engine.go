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
	for _, p := range e.planners {
		actions, err := p.Plan(ctx, spec)
		if err != nil {
			err = fmt.Errorf("plan %s: %w", p.Component(), err)
			e.log.Error("component did not converge", "component", p.Component(), "err", err)
			report.Plans = append(report.Plans, Plan{Component: p.Component(), Err: err})
			failed = append(failed, err)
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
