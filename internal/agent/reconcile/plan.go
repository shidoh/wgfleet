// Package reconcile is the agent's convergence engine. Its central contract is
// docs/DESIGN.md principle #4: every reconcile can run in plan (dry-run) mode, which
// renders the desired artifacts and the changes they imply WITHOUT mutating the
// node. Apply mode performs exactly the actions plan showed.
//
// A Planner produces a slice of Actions from the desired NodeSpec. Each Action
// is self-contained: it carries a human-safe Display (secrets redacted) for
// plan output and an apply closure for apply mode. The Engine renders all
// planners, prints/collects the plan, and — only in apply mode — runs each
// action's closure.
package reconcile

import (
	"context"
	"fmt"
	"strings"
)

// Mode selects dry-run vs. real application.
type Mode int

const (
	// ModePlan renders and diffs but changes nothing (dry-run).
	ModePlan Mode = iota
	// ModeApply performs the rendered changes.
	ModeApply
)

func (m Mode) String() string {
	if m == ModeApply {
		return "apply"
	}
	return "plan"
}

// ActionKind classifies what an action would do.
type ActionKind string

const (
	ActionCreate   ActionKind = "create"    // target does not exist; would be created
	ActionUpdate   ActionKind = "update"    // target exists and differs; would be rewritten
	ActionNoChange ActionKind = "no-change" // target already matches desired state
	ActionDelete   ActionKind = "delete"    // target would be removed
	ActionExec     ActionKind = "exec"      // a command would be executed
)

// Action is one intended change. apply is nil for ActionNoChange. Display is the
// human-safe rendering shown in plan mode; it never contains secrets.
type Action struct {
	Kind    ActionKind
	Target  string // file path or resource label
	Summary string // one-line description
	Display string // redacted artifact, diff, or command shown in plan output
	apply   func(ctx context.Context) error
}

// Changes reports whether the action would mutate anything.
//
// CAUTION for callers that gate a restart or reload on this: it does NOT tell you
// WHAT changed. A FileAction returns an update for a pure permission repair
// (content identical, mode wrong) exactly as it does for a content rewrite, so a
// planner written as `if file.Changes() { restart() }` will bounce a service over a
// chmod. Both current callers survive that by luck rather than design —
// composePlanner's `docker compose up -d` is idempotent, and mihomoPlanner's
// restart decision runs through mihomo.ProxiesChanged, which compares bytes and so
// correctly ignores a mode-only change. A future caller mapping Changes() straight
// to "must restart" would not be so lucky: compare content explicitly.
func (a Action) Changes() bool { return a.Kind != ActionNoChange }

// run executes the action's effect, or is a no-op when there is nothing to do.
func (a Action) run(ctx context.Context) error {
	if a.apply == nil || !a.Changes() {
		return nil
	}
	return a.apply(ctx)
}

// Plan is the set of actions one planner would take.
type Plan struct {
	Component string
	// Scheduled marks a plan whose changes are driven by an out-of-band schedule
	// (e.g. a timer-based feed refresh) rather than by divergence from the desired
	// spec. Such expected changes are excluded from drift accounting. The engine
	// sets it from a planner that implements ScheduledPlanner.
	Scheduled bool
	Actions   []Action
}

// HasChanges reports whether any action in the plan mutates state.
func (p Plan) HasChanges() bool {
	for _, a := range p.Actions {
		if a.Changes() {
			return true
		}
	}
	return false
}

// Report is the aggregate of every planner's plan in one reconcile pass.
type Report struct {
	Mode  Mode
	Plans []Plan
}

// ChangedComponents returns the names of the components that (would) mutate
// state, in plan order, each listed once. On a converged node this is empty; on
// a drift-repair pass it names exactly which subsystems diverged.
func (r Report) ChangedComponents() []string {
	var names []string
	for _, p := range r.Plans {
		if p.HasChanges() {
			names = append(names, p.Component)
		}
	}
	return names
}

// DriftComponents is ChangedComponents minus any plan flagged Scheduled. A
// scheduled planner (e.g. the AS-blacklist feed refresh) mutates the node on its
// own timer, independently of the desired spec, so its expected change is NOT
// configuration drift and must not be reported as such — otherwise the daily
// refresh would WARN and bump agent_drift_total every cycle. Use this, not
// ChangedComponents, for drift detection.
func (r Report) DriftComponents() []string {
	var names []string
	for _, p := range r.Plans {
		if p.Scheduled || !p.HasChanges() {
			continue
		}
		names = append(names, p.Component)
	}
	return names
}

// ChangeCount returns the number of actions that (would) mutate state.
func (r Report) ChangeCount() int {
	n := 0
	for _, p := range r.Plans {
		for _, a := range p.Actions {
			if a.Changes() {
				n++
			}
		}
	}
	return n
}

// String renders the whole report as a readable plan, suitable for printing in
// dry-run mode. It groups actions by component and shows each rendered artifact.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "reconcile %s — %d change(s)\n", r.Mode, r.ChangeCount())
	for _, p := range r.Plans {
		fmt.Fprintf(&b, "\n=== %s ===\n", p.Component)
		if len(p.Actions) == 0 {
			b.WriteString("  (nothing to do)\n")
			continue
		}
		for _, a := range p.Actions {
			marker := changeMarker(a.Kind)
			fmt.Fprintf(&b, "  %s %-9s %s — %s\n", marker, a.Kind, a.Target, a.Summary)
			if a.Display != "" && a.Kind != ActionNoChange {
				b.WriteString(indent(a.Display, "      | "))
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

func changeMarker(k ActionKind) string {
	switch k {
	case ActionCreate:
		return "+"
	case ActionUpdate:
		return "~"
	case ActionDelete:
		return "-"
	case ActionExec:
		return "!"
	default:
		return " "
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
