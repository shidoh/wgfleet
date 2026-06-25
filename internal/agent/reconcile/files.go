package reconcile

import (
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
		var redact Redactor
		if f.Secret {
			redact = secretFileRedactor
		}
		a, err := FileAction(target, []byte(f.Content), 0o644, redact)
		if err != nil {
			return nil, err
		}
		actions = append(actions, a)
	}
	return actions, nil
}
