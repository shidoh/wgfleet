package reconcile

import (
	"context"
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
// callers can print exactly what would change. A planner error aborts the pass;
// in apply mode, actions already applied are not rolled back (reconcile is
// idempotent, so a re-run converges).
func (e *Engine) Reconcile(ctx context.Context, spec domain.NodeSpec, mode Mode) (Report, error) {
	report := Report{Mode: mode}
	for _, p := range e.planners {
		actions, err := p.Plan(ctx, spec)
		if err != nil {
			return report, fmt.Errorf("plan %s: %w", p.Component(), err)
		}
		report.Plans = append(report.Plans, Plan{Component: p.Component(), Actions: actions})

		if mode != ModeApply {
			continue
		}
		for _, a := range actions {
			if !a.Changes() {
				continue
			}
			e.log.Info("applying action", "component", p.Component(),
				"kind", a.Kind, "target", a.Target)
			if err := a.run(ctx); err != nil {
				return report, fmt.Errorf("apply %s/%s (%s): %w", p.Component(), a.Target, a.Kind, err)
			}
		}
	}
	return report, nil
}
