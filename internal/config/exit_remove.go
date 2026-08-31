package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
)

// ErrExitNotDeclared reports that the manifest does not declare the named exit, so
// there was nothing to remove. Callers whose goal is the END STATE ("this node is
// not declared") should treat it as success: the controller reads the manifest once
// at startup and never reloads it, so a delete that already rewrote the file leaves
// the running process still offering the node from its startup snapshot — and the
// operator pressing Delete a second time on that stale card must not be told the
// removal failed when the file already says what they want it to say.
var ErrExitNotDeclared = errors.New("exit not declared in manifest")

// RemoveExit deletes an exit's declaration from the controller manifest at path,
// in place, preserving every other line (comments, formatting, ordering) verbatim.
// It is the durable half of deleting a node from the console: the store row is the
// node's live state, but the manifest is what DECLARES the node exists, so removing
// only the row leaves the node reappearing as a Pending stub on the next page load
// (Handler.nodes re-adds every declared exit the store does not know). A node whose
// server is gone can only be removed here.
//
// Two edits, because they are one change: the exit's `- name:` block is dropped
// from fleet.exits, and the name is pruned from every masters[].routing.reserve_exits
// that lists it. The second is not tidiness — validateReserveExits REJECTS an entry
// naming no declared exit, so dropping the block alone yields a manifest the
// controller refuses to start on. Deleting a node from the UI must never hand the
// operator a control plane that will not come back up.
//
// The write is atomic (temp file + rename), serialized against the manifest's other
// writer (see manifestWrite), and forces the secret-bearing manifest to 0600. An
// exit the manifest does not declare yields ErrExitNotDeclared and leaves the file
// untouched.
//
// A comment written ABOVE the `- name:` line is deliberately left in place, even
// though it may have described the exit that just went (it then reads as a heading
// for the next one). Consuming it would be the tidier output and the worse
// behaviour: a comment at that indent is just as often a heading for the list or a
// note the operator left themselves, and silently deleting prose someone wrote is
// not something an automated edit gets to guess at. An orphaned line the operator
// can see and remove beats a lost one they cannot.

func RemoveExit(path, exitName string) error {
	manifestWrite.Lock()
	defer manifestWrite.Unlock()

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", path, err)
	}
	// Preserve a trailing newline: split keeps a trailing "" we rejoin with "\n".
	lines := strings.Split(string(raw), "\n")

	// Scope the search to fleet.exits. findExitNameLine matches `- name: X` ANYWHERE
	// in the file, and `fleet.masters` entries have the same shape — so an unscoped
	// search for a master's name finds the MASTER's block and removes it, leaving a
	// fleet with no master. That config still loads, so there is no crash to notice:
	// the controller comes up and brokers a fleet that has no hub. Nothing may ever
	// ask this to remove a master, but "nothing asks" is not a property this function
	// can rely on, and the damage is silent.
	from, to, ok := findExitsSection(lines)
	if !ok {
		return fmt.Errorf("no fleet.exits section in manifest %q", path)
	}
	nameIdx, nameIndent, found := findExitNameLine(lines[from:to], exitName)
	if !found {
		// Do NOT report "not declared" on the strength of the line scanner's own
		// negative. Callers treat ErrExitNotDeclared as success ("the end state is
		// what I wanted"), so every way this text matcher can fail to see a line —
		// an unanticipated spelling, a section-scoping slip, a formatting style it
		// was never taught — would otherwise become a delete that reports success
		// and removes nothing. Ask the YAML parser instead: it is a structurally
		// independent answer to the only question that matters here.
		declared, perr := declaresExit(raw, exitName)
		switch {
		case perr != nil:
			return fmt.Errorf("exit %q not matched in manifest %q, and it could not be parsed to confirm: %w", exitName, path, perr)
		case declared:
			return fmt.Errorf("manifest %q declares exit %q but its block could not be located for removal; "+
				"remove it by hand (unsupported formatting?)", path, exitName)
		}
		return fmt.Errorf("exit %q in manifest %q: %w", exitName, path, ErrExitNotDeclared)
	}
	nameIdx += from

	// The block runs from its `- name:` line to the next line at or below the dash
	// indent (the next sibling exit, or a dedent out of the list). Blank lines and
	// more-indented comments inside belong to the block and go with it.
	end := to
	for i := nameIdx + 1; i < to; i++ {
		if blockEnded(lines[i], nameIndent) {
			end = i
			break
		}
	}
	// Trailing blank lines swept up by the scan above belong to the separation
	// between entries, not to this one; leave them so the file's spacing survives.
	for end > nameIdx+1 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	lines = append(lines[:nameIdx], lines[end:]...)

	lines = pruneReserveExits(lines, exitName)

	return writeFileAtomic(path, []byte(strings.Join(lines, "\n")))
}

// pruneReserveExits removes exitName from every `reserve_exits` list in lines,
// handling both shapes an operator writes: the inline flow sequence
// (`reserve_exits: [anz3, fn7, pn8]`) and the block sequence (`reserve_exits:`
// followed by `- fn7` items). Lists that do not mention the name are untouched.
func pruneReserveExits(lines []string, exitName string) []string {
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if !keyIs(l, "reserve_exits") {
			out = append(out, l)
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "reserve_exits:"))
		if value != "" {
			out = append(out, pruneInlineList(l, value, exitName))
			continue
		}
		// Block form: keep the key, then drop the matching `- <name>` item from the
		// more-indented list that follows.
		out = append(out, l)
		for i+1 < len(lines) {
			next := lines[i+1]
			trimmed := strings.TrimSpace(next)
			nextIndent := len(next) - len(strings.TrimLeft(next, " "))
			if trimmed == "" || nextIndent <= indent || !strings.HasPrefix(trimmed, "- ") {
				break
			}
			i++
			if scalarValue(trimmed[2:]) != exitName {
				out = append(out, next)
			}
		}
	}
	return out
}

// pruneInlineList rewrites `reserve_exits: [a, b, c]` without exitName, keeping the
// line's indent and the `[a, b]` spelling the operator used. A value that is not a
// flow sequence (an anchor, say) is left alone rather than mangled.
func pruneInlineList(line, value, exitName string) string {
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return line
	}
	indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
	inner := strings.TrimSpace(value[1 : len(value)-1])
	kept := make([]string, 0)
	if inner != "" {
		for item := range strings.SplitSeq(inner, ",") {
			if name := unquote(strings.TrimSpace(item)); name != exitName && name != "" {
				kept = append(kept, name)
			}
		}
	}
	// Keep the line's own ending: this is the one line we rewrite from scratch, and
	// emitting it LF-only inside a CRLF file would leave a single mixed-ending line.
	eol := ""
	if strings.HasSuffix(line, "\r") {
		eol = "\r"
	}
	return indent + "reserve_exits: [" + strings.Join(kept, ", ") + "]" + eol
}

// scalarValue extracts a YAML scalar from the text after a key, dropping the
// optional quoting and any trailing `# comment`. This manifest annotates values
// heavily, so `- name: fn7  # dead server` is an ordinary thing to find — and a
// matcher that misses it makes a declared exit look absent, which is the one
// mistake this code must never make quietly.
func scalarValue(s string) string {
	s = strings.TrimSpace(s)
	// A quoted scalar owns everything up to its closing quote; only what follows can
	// be a comment, so scanning for "#" before that would cut inside the value.
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		if end := strings.IndexByte(s[1:], s[0]); end >= 0 {
			return s[1 : 1+end]
		}
		return s
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// unquote strips the optional YAML quoting around a scalar.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// findExitsSection returns the half-open line range [from, to) holding the items of
// the top-level `fleet.exits:` list. Bounding the search matters because a manifest
// has several lists of `- name:` items (fleet.masters most of all) and an unbounded
// match would let a removal reach into the wrong one.
func findExitsSection(lines []string) (from, to int, ok bool) {
	fleetIdx := -1
	for i, l := range lines {
		if keyIs(l, "fleet") && indentOf(l) == 0 {
			fleetIdx = i
			break
		}
	}
	if fleetIdx < 0 {
		return 0, 0, false
	}
	childIndent := -1
	for i := fleetIdx + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			continue
		}
		if indentOf(l) == 0 { // out of the fleet block without finding exits
			return 0, 0, false
		}
		// The first non-blank line inside the block fixes the indent of fleet's direct
		// children; anything deeper belongs to one of them. Without this, a key spelled
		// `exits:` nested under (say) masters[].routing would be taken for the exit list
		// and hand back the wrong range — the same class of mistake as matching a
		// master's `- name:`, one level further in.
		if childIndent < 0 {
			childIndent = indentOf(l)
		}
		if !keyIs(l, "exits") || indentOf(l) != childIndent {
			continue
		}
		exitsIndent := indentOf(l)
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "" {
				continue
			}
			if indentOf(lines[j]) <= exitsIndent {
				end = j
				break
			}
		}
		return i + 1, end, true
	}
	return 0, 0, false
}

// indentOf is the count of leading spaces on a line.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// declaresExit answers, from the YAML parser rather than the line scanner, whether
// the manifest declares an exit by this name. It exists so a failure of the text
// matcher can never be mistaken for "the exit is not there" — the two look
// identical from inside RemoveExit, and callers treat the latter as success.
// It parses only; a manifest that would fail Validate() still answers this question.
func declaresExit(raw []byte, exitName string) (bool, error) {
	tree, err := yaml.Parser().Unmarshal(raw)
	if err != nil {
		return false, fmt.Errorf("parse manifest: %w", err)
	}
	fleet, ok := tree["fleet"].(map[string]any)
	if !ok {
		return false, nil
	}
	exits, ok := fleet["exits"].([]any)
	if !ok {
		return false, nil
	}
	for _, item := range exits {
		e, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := e["name"].(string); ok && name == exitName {
			return true, nil
		}
	}
	return false, nil
}
