package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Redactor masks secrets in rendered content before it is shown in plan output.
// It is applied only to Display; the real content is still written on apply.
type Redactor func(string) string

// FileAction computes the action needed to make target hold content. It reads
// the current file to classify the change (create/update/no-change) and builds
// an apply closure that writes content atomically with perm. Display is the
// redacted content, safe to print in dry-run.
func FileAction(target string, content []byte, perm os.FileMode, redact Redactor) (Action, error) {
	display := string(content)
	if redact != nil {
		display = redact(display)
	}

	existing, err := os.ReadFile(target)
	kind := ActionUpdate
	switch {
	case errors.Is(err, fs.ErrNotExist):
		kind = ActionCreate
	case err != nil:
		return Action{}, fmt.Errorf("read %q: %w", target, err)
	case bytes.Equal(existing, content):
		kind = ActionNoChange
	}

	a := Action{
		Kind:    kind,
		Target:  target,
		Summary: fmt.Sprintf("%d bytes, mode %o", len(content), perm),
		Display: display,
	}
	if kind != ActionNoChange {
		// Capture content/perm by value for the closure.
		data := append([]byte(nil), content...)
		a.apply = func(context.Context) error { return atomicWrite(target, data, perm) }
	}
	return a, nil
}

// ExecAction describes a command to run in apply mode. In plan mode only its
// Display (the command line) is shown. cmd[0] is the binary; the rest are args.
func ExecAction(summary string, cmd ...string) Action {
	display := strings.Join(cmd, " ")
	a := Action{
		Kind:    ActionExec,
		Target:  commandLabel(cmd),
		Summary: summary,
		Display: display,
	}
	captured := append([]string(nil), cmd...)
	a.apply = func(ctx context.Context) error {
		if len(captured) == 0 {
			return errors.New("empty command")
		}
		c := exec.CommandContext(ctx, captured[0], captured[1:]...)
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", display, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return a
}

// BestEffortExecAction is like ExecAction but its failure is non-fatal: the
// command runs in apply mode and any error is swallowed. Use for teardown /
// cleanup, where a step may legitimately no-op (an interface already down, a
// service already stopped) and one failure must not abort the rest.
func BestEffortExecAction(summary string, cmd ...string) Action {
	a := ExecAction(summary, cmd...)
	inner := a.apply
	display := a.Display
	a.apply = func(ctx context.Context) error {
		if inner != nil {
			// Non-fatal, but never silent: a best-effort step that fails for a real
			// reason (device busy, missing binary) must leave a trace, or the only
			// visible symptom is a misleading failure in a later step.
			if err := inner(ctx); err != nil {
				slog.Warn("best-effort action failed (non-fatal)", "cmd", display, "err", err)
			}
		}
		return nil
	}
	return a
}

// RemoveFileAction deletes target. It classifies by reading current state — a
// delete when the file exists, a no-change when it is already gone — so plan
// output is honest and the wipe is idempotent. Apply is best-effort: a file that
// vanished concurrently or cannot be removed never aborts the pass, matching the
// teardown/decommission flow this is built for (the node is going away). Display
// is empty: there is no content to show, only the path.
func RemoveFileAction(target, summary string) (Action, error) {
	_, err := os.Stat(target)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return NoChangeAction(target, "already absent"), nil
	case err != nil:
		return Action{}, fmt.Errorf("stat %q: %w", target, err)
	}
	a := Action{Kind: ActionDelete, Target: target, Summary: summary}
	a.apply = func(context.Context) error {
		_ = os.Remove(target) // best-effort: teardown tolerates a failed wipe
		return nil
	}
	return a, nil
}

// NoChangeAction records that a resource already matches desired state, so plan
// output can show it explicitly rather than silently omitting it.
func NoChangeAction(target, summary string) Action {
	return Action{Kind: ActionNoChange, Target: target, Summary: summary}
}

// CustomAction builds an action with an explicit kind and apply closure, for
// effects that are neither file writes nor command execs (e.g. a database
// update). The planner decides the kind by reading current state; pass display
// already redacted. apply is run only in apply mode and only when the kind
// changes state.
func CustomAction(kind ActionKind, target, summary, display string, apply func(ctx context.Context) error) Action {
	a := Action{Kind: kind, Target: target, Summary: summary, Display: display}
	if kind != ActionNoChange {
		a.apply = apply
	}
	return a
}

func commandLabel(cmd []string) string {
	if len(cmd) == 0 {
		return "(empty)"
	}
	return filepath.Base(cmd[0])
}

// atomicWrite writes data to a temp file in the same directory and renames it
// over target, so readers never observe a half-written config.
func atomicWrite(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".wgfleet-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("rename temp over %q: %w", target, err)
	}
	return nil
}
