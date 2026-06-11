package provisioner

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// Mode selects dry-run vs. real execution, mirroring the agent reconcile engine.
type Mode int

const (
	// ModePlan renders the bootstrap plan but executes nothing.
	ModePlan Mode = iota
	// ModeApply executes the bootstrap steps over SSH.
	ModeApply
)

func (m Mode) String() string {
	if m == ModeApply {
		return "apply"
	}
	return "plan"
}

// StepKind classifies a bootstrap step.
type StepKind string

const (
	StepCheck  StepKind = "check"  // read-only fact/precondition check
	StepRun    StepKind = "run"    // a command that changes the node
	StepUpload StepKind = "upload" // a file written to the node
)

// Step is one bootstrap action. exec performs it via the Runner; Display is the
// human-safe rendering shown in plan mode (secrets redacted). Steps are ordered.
type Step struct {
	Kind    StepKind
	Summary string
	Display string
	exec    func(ctx context.Context, r Runner) error
}

// runStep builds a command Step.
func runStep(summary, cmd string) Step {
	return Step{
		Kind:    StepRun,
		Summary: summary,
		Display: cmd,
		exec: func(ctx context.Context, r Runner) error {
			out, err := r.Run(ctx, cmd)
			if err != nil {
				return fmt.Errorf("%s: %w (output: %s)", summary, err, strings.TrimSpace(out))
			}
			return nil
		},
	}
}

// uploadStep builds a file-upload Step. displayContent is what plan mode shows
// (redact secrets before passing it here); content is what is actually written.
func uploadStep(summary, remotePath string, content []byte, mode os.FileMode, displayContent string) Step {
	data := append([]byte(nil), content...)
	return Step{
		Kind:    StepUpload,
		Summary: summary,
		Display: fmt.Sprintf("upload %s (%d bytes, mode %o)\n%s", remotePath, len(content), mode, displayContent),
		exec: func(ctx context.Context, r Runner) error {
			return r.Upload(ctx, remotePath, data, mode)
		},
	}
}

// checkStep builds a read-only precondition step. fn returns an error to abort
// provisioning (e.g. a missing AmneziaWG kernel module — surfaced, not swallowed).
func checkStep(summary, cmd string, fn func(ctx context.Context, r Runner) error) Step {
	return Step{
		Kind:    StepCheck,
		Summary: summary,
		Display: cmd,
		exec:    fn,
	}
}

// Plan is the ordered set of bootstrap steps for one node.
type Plan struct {
	Node  string
	Steps []Step
}

// Report is the outcome of a provisioning pass.
type Report struct {
	Mode Mode
	Plan Plan
}

// String renders the plan for printing in dry-run mode.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "provision %s — node %q, %d step(s)\n", r.Mode, r.Plan.Node, len(r.Plan.Steps))
	for i, s := range r.Plan.Steps {
		fmt.Fprintf(&b, "\n  %2d. [%s] %s\n", i+1, s.Kind, s.Summary)
		if s.Display != "" {
			b.WriteString(indent(s.Display, "      | "))
			b.WriteString("\n")
		}
	}
	return b.String()
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
