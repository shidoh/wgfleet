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
	// A redactor is the caller's own declaration that this content carries secrets.
	// Redaction only ever applies to the plan/dry-run Display string — the bytes
	// written to disk are the real thing — so the ONLY at-rest control is the mode.
	// Refuse to write secret-bearing content group/world-readable.
	//
	// This existed as a convention the exit side followed (0600 alongside
	// wg.RedactConfig / xray.RedactConfig) and the master side quietly broke: the
	// rendered mihomo config went out 0644 while holding one WireGuard private key
	// per exit, and the master compose file 0644 while holding a container admin
	// password. Found in review 2026-07-20. A convention that is only documented
	// gets violated; make it an invariant the code enforces.
	if redact != nil && perm&0o077 != 0 {
		return Action{}, fmt.Errorf("refusing to write %q with mode %#o: content is "+
			"secret-bearing (a redactor was supplied) and must not be group/world-readable", target, perm)
	}

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

	// Mode drift is a change even when the bytes match. The mode is only ever
	// applied on a write, so a file whose content is already current keeps whatever
	// mode it has — including one left behind by an older binary, a hand-edit, or a
	// bad umask. That is how /etc/wgfleet/docker-compose.yml sat at 0644 holding a
	// container admin password AFTER both the code fix and a manual chmod: the fix
	// landed, the content never changed again, so nothing re-applied the mode.
	//
	// Repairing it here rather than in each caller matters because this is the one
	// place that knows the DESIRED mode; a reconciler whose job is convergence must
	// converge permissions too, not only bytes (ADR-0015 drift repair).
	modeDrift := false
	if kind == ActionNoChange {
		if fi, serr := os.Stat(target); serr == nil && fi.Mode().Perm() != perm {
			modeDrift = true
			kind = ActionUpdate
		}
	}

	summary := fmt.Sprintf("%d bytes, mode %o", len(content), perm)
	if modeDrift {
		summary = fmt.Sprintf("content current; repairing mode to %o", perm)
	}
	a := Action{
		Kind:    kind,
		Target:  target,
		Summary: summary,
		Display: display,
	}
	switch {
	case modeDrift:
		// Content already matches, so a chmod is enough — rewriting the bytes would
		// churn the file's mtime and, for watched files, trigger needless reloads.
		a.apply = func(context.Context) error {
			if cerr := os.Chmod(target, perm); cerr != nil {
				return fmt.Errorf("repair mode on %q: %w", target, cerr)
			}
			return nil
		}
	case kind != ActionNoChange:
		// Capture content/perm by value for the closure.
		data := append([]byte(nil), content...)
		a.apply = func(context.Context) error { return AtomicWrite(target, data, perm) }
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
	return ExecAction(summary, cmd...).BestEffort()
}

// BestEffort returns a copy of a whose failure is logged and swallowed.
//
// Separate from BestEffortExecAction so it can wrap an action that already has an
// OnApplied hook: the hook then fires only on a real success, and the failure is
// still non-fatal to the pass. Composing it the other way round — best-effort
// first, hook second — would fire the hook on failure too, because the wrapper
// reports success unconditionally.
func (a Action) BestEffort() Action {
	a.NonFatal = true
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

// OnlyIf re-asks, at APPLY time, a question the plan answered from a snapshot.
//
// A plan is computed from the world as it was at the start of the pass, and every
// action in it is then applied in order — so an action can run against a world its
// own predecessors failed to build. That is not hypothetical: the rule that sends
// clients into mihomo's namespace is preceded by the two commands that make the
// table it points at usable, and all three are best-effort. Both of them failing
// and the third one running anyway is exactly the state the ordering exists to
// prevent, because a rule pointing at an empty table does not fail — it routes
// every client out of the uplink until the next pass.
//
// The skip is an error rather than a silent no-op: composed under BestEffort it
// becomes a warning naming the reason, and a step that quietly did not happen is
// the hardest kind to find.
func (a Action) OnlyIf(because string, cond func(ctx context.Context) bool) Action {
	a.guard = cond
	inner := a.apply
	a.apply = func(ctx context.Context) error {
		if !cond(ctx) {
			return fmt.Errorf("skipped: %s", because)
		}
		if inner == nil {
			return nil
		}
		return inner(ctx)
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

// AtomicWrite writes data to a temp file in the same directory and renames it
// over target, so readers never observe a half-written config.
func AtomicWrite(target string, data []byte, perm os.FileMode) error {
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
