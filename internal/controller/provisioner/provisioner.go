package provisioner

import (
	"context"
	"fmt"
	"log/slog"
)

// Provisioner runs the bootstrap pipeline for a node over a Runner. It is
// constructed with a logger; the Runner is passed per call so the controller can
// dial SSH (or inject a mock) at provisioning time.
type Provisioner struct {
	log *slog.Logger
}

// New returns a Provisioner.
func New(log *slog.Logger) *Provisioner {
	if log == nil {
		log = slog.Default()
	}
	return &Provisioner{log: log}
}

// Provision collects facts, runs preflight, builds the bootstrap plan, and — in
// ModeApply — executes it over the Runner. In ModePlan it returns the Report
// without running any mutating step (read-only fact collection still happens, so
// the plan reflects the node's real state). The caller supplies everything in
// BootstrapInput except Facts, which Provision fills in.
func (p *Provisioner) Provision(ctx context.Context, r Runner, in BootstrapInput, mode Mode) (Report, error) {
	facts, err := CollectFacts(ctx, r)
	if err != nil {
		return Report{}, fmt.Errorf("collect facts for %q: %w", in.Node.Name, err)
	}
	if err := facts.Preflight(); err != nil {
		return Report{}, fmt.Errorf("preflight %q: %w", in.Node.Name, err)
	}
	in.Facts = facts

	plan := BuildPlan(in)
	report := Report{Mode: mode, Plan: plan}

	if mode != ModeApply {
		return report, nil
	}

	for i, step := range plan.Steps {
		p.log.Info("bootstrap step", "node", in.Node.Name, "step", i+1,
			"kind", step.Kind, "summary", step.Summary)
		if step.exec == nil {
			continue
		}
		if err := step.exec(ctx, r); err != nil {
			return report, fmt.Errorf("step %d (%s): %w", i+1, step.Summary, err)
		}
	}
	p.log.Info("bootstrap complete", "node", in.Node.Name, "steps", len(plan.Steps))
	return report, nil
}
