package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// SetExitActiveTransport rewrites the `active_transport` of a single exit in the
// controller manifest at path, in place, preserving every other line (comments,
// formatting, ordering) verbatim. It is the durable half of the Web UI transport
// switch (ADR-0025): the store override gives the live effect, this makes the
// manifest — the platform's source of truth — agree, so the change survives a
// controller restart and a node delete/re-provision.
//
// If the exit's block already has an `active_transport:` line it is replaced;
// otherwise one is inserted right after the exit's `- name:` line at the matching
// indent. The write is atomic (temp file + rename) and preserves the file mode.
// An unknown exit is an error — we never silently no-op a switch the operator asked for.
func SetExitActiveTransport(path, exitName string, t domain.MasterTransport) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", path, err)
	}
	// Preserve a trailing newline: split keeps a trailing "" we rejoin with "\n".
	lines := strings.Split(string(raw), "\n")

	nameIdx, nameIndent, found := findExitNameLine(lines, exitName)
	if !found {
		return fmt.Errorf("exit %q not found in manifest %q", exitName, path)
	}

	propIndent := strings.Repeat(" ", nameIndent+2)
	newLine := propIndent + "active_transport: " + string(t)

	// Search the exit's block (lines more-indented than the `- name:` line, until
	// the next sibling/dedent) for an existing active_transport key.
	replaced := false
	for i := nameIdx + 1; i < len(lines); i++ {
		if blockEnded(lines[i], nameIndent) {
			break
		}
		if keyIs(lines[i], "active_transport") {
			lines[i] = newLine
			replaced = true
			break
		}
	}
	if !replaced {
		// Insert right after the `- name:` line.
		lines = append(lines, "")
		copy(lines[nameIdx+2:], lines[nameIdx+1:])
		lines[nameIdx+1] = newLine
	}

	return writeFileAtomic(path, []byte(strings.Join(lines, "\n")))
}

// findExitNameLine returns the index and the dash indent of the `- name: <exitName>`
// list item. Names are fleet-unique, so a plain value match is unambiguous.
func findExitNameLine(lines []string, exitName string) (idx, indent int, found bool) {
	for i, l := range lines {
		trimmed := strings.TrimLeft(l, " ")
		if !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		rest := strings.TrimSpace(trimmed[2:])
		if rest == "name: "+exitName || rest == "name: \""+exitName+"\"" {
			return i, len(l) - len(trimmed), true
		}
	}
	return 0, 0, false
}

// blockEnded reports whether line is non-blank and indented at or below the list
// item's dash — i.e. the exit's block has ended (next sibling or a dedent). Blank
// lines and comments inside the block do not end it.
func blockEnded(line string, nameIndent int) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}
	indent := len(line) - len(strings.TrimLeft(line, " "))
	return indent <= nameIndent
}

// keyIs reports whether a line is the mapping key `key:` (ignoring indentation).
func keyIs(line, key string) bool {
	s := strings.TrimSpace(line)
	return s == key+":" || strings.HasPrefix(s, key+": ")
}

// writeFileAtomic writes data to a temp file in the same directory and renames it
// over path, preserving path's mode so a 0600 manifest stays 0600.
func writeFileAtomic(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".controller-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp manifest in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp manifest: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod temp manifest: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename manifest into place: %w", err)
	}
	return nil
}
