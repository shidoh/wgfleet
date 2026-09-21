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
	facts, err := CollectFacts(ctx, r, in.Node.MgmtAddr)
	if err != nil {
		return Report{}, fmt.Errorf("collect facts for %q: %w", in.Node.Name, err)
	}
	if err := facts.Preflight(); err != nil {
		return Report{}, fmt.Errorf("preflight %q: %w", in.Node.Name, err)
	}
	in.Facts = facts

	return p.run(ctx, r, BuildPlan(in), mode, "bootstrap")
}

// Upgrade rolls the node's agent binary forward in place (upload + restart),
// without re-running the full bootstrap. In ModePlan it returns the plan without
// touching the node. The caller supplies BootstrapInput.Node and AgentBinary;
// the rest of BootstrapInput is unused here (identity/deps already on the node).
func (p *Provisioner) Upgrade(ctx context.Context, r Runner, in BootstrapInput, mode Mode) (Report, error) {
	return p.run(ctx, r, BuildUpgradePlan(in), mode, "upgrade")
}

// Rollback restores the agent binary a previous Upgrade displaced (<bin>.prev)
// and restarts the service. It is the recovery half of a rolling upgrade: SSH is
// independent of the agent, so a node whose new binary will not run is still
// reachable to be put back on the one that did.
func (p *Provisioner) Rollback(ctx context.Context, r Runner, node string, mode Mode) (Report, error) {
	return p.run(ctx, r, BuildRollbackPlan(node), mode, "rollback")
}

// run executes (or, in ModePlan, just returns) an ordered plan over the Runner.
func (p *Provisioner) run(ctx context.Context, r Runner, plan Plan, mode Mode, kind string) (Report, error) {
	report := Report{Mode: mode, Plan: plan}
	if mode != ModeApply {
		return report, nil
	}
	for i, step := range plan.Steps {
		p.log.Info(kind+" step", "node", plan.Node, "step", i+1,
			"kind", step.Kind, "summary", step.Summary)
		if step.exec == nil {
			continue
		}
		if err := step.exec(ctx, r); err != nil {
			return report, fmt.Errorf("step %d (%s): %w", i+1, step.Summary, err)
		}
	}
	p.log.Info(kind+" complete", "node", plan.Node, "steps", len(plan.Steps))
	return report, nil
}
