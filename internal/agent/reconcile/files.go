package reconcile

import (
	"os"
	"path/filepath"

	"github.com/shidoh/wgfleet/internal/domain"
)

// secretFileRedactor masks an operator-supplied secret file's content in plan
// output (the real content is still written on apply).
func secretFileRedactor(string) string { return "<redacted: operator secret file>" }

// ManagedFileActions turns a slice of operator-managed extra files (CustomConfig.
// Files) into FileActions. Relative paths are resolved against baseDir; absolute
// paths are written as given. Secret files are redacted in plan output. It is the
// shared implementation behind every reconciler that writes Custom.Files (the
// exit/master DNS planners and the master extra-files planner).
func ManagedFileActions(files []domain.ManagedFile, baseDir string) ([]Action, error) {
	actions := make([]Action, 0, len(files))
	for _, f := range files {
		target := f.Path
		if !filepath.IsAbs(target) {
			target = filepath.Join(baseDir, target)
		}
		// A secret file is written 0600, not 0644. FileAction refuses the pair
		// (redactor, group-readable mode) on purpose — redaction only hides the
		// content from plan output, so the mode is the only at-rest control. Passing
		// 0644 here made that refusal fire on the operator's own config: `custom.files`
		// with `secret: true` returned an error out of every planner that writes them,
		// and the node stopped converging entirely, on every pass, for good.
		perm := os.FileMode(0o644)
		var redact Redactor
		if f.Secret {
			perm = 0o600
			redact = secretFileRedactor
		}
		a, err := FileAction(target, []byte(f.Content), perm, redact)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}
	return actions, nil
}
