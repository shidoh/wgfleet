package support

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// secretKeyRe matches a line whose KEY names it as secret-bearing, in either
// `key: value` or `key = value` or `key=value` form. Used by both Scrub (mask)
// and Gate (refuse) — it is the coarse layer, for uncontrolled text such as
// container logs where we do not control the format.
var secretKeyRe = regexp.MustCompile(`(?i)\b(private[_-]?key|pre[_-]?shared[_-]?key|secret|password|passwd|token|authorization|api[_-]?key)\b\s*[:=]\s*(\S+)`)

// redactedMarker is what an already-masked value looks like. The renderers emit
// it, so the gate must treat it as safe rather than as a surviving secret.
const redactedMarker = "<redacted>"

// LeakError reports that the assembled bundle still contained something secret.
// It names the file and line but NEVER the value: an error message is the one
// place a leak-detector must not leak.
type LeakError struct {
	File   string
	Line   int
	Reason string
}

func (e *LeakError) Error() string {
	return fmt.Sprintf("refusing to write the bundle: %s:%d %s", e.File, e.Line, e.Reason)
}

// Scrub masks the value of any secret-bearing key, preserving the key and its
// separator (":" or "=") verbatim. Defence in depth for text we do not
// control; it is not the guarantee — Collect's allowlist is.
func Scrub(s string) string {
	matches := secretKeyRe.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}

	var b strings.Builder
	last := 0
	for _, m := range matches {
		// m[4], m[5] bound submatch 2 — the value — inside the whole match.
		valStart, valEnd := m[4], m[5]
		b.WriteString(s[last:valStart])
		b.WriteString(redactedMarker)
		last = valEnd
	}
	b.WriteString(s[last:])
	return b.String()
}

// Gate is the last line: it refuses to write rather than writing something
// redacted-in-passing. Two checks, in order of strength:
//
//  1. Exact — every value in secrets is searched for verbatim. The node holds
//     its own real keys, so this is precise and has no false positives. It is
//     the primary check because AmneziaWG public and private keys share a shape
//     and no regex can tell them apart.
//  2. By key name — for a secret this process does not know about, arriving in
//     uncontrolled text.
//
// Empty or whitespace-only entries in secrets are skipped: strings.Contains with
// an empty needle is always true, and one such entry would fail every bundle.
//
// Files are walked in sorted name order (nodes by Name, then files by name
// within each node) so the first hit reported is deterministic.
func Gate(nodes []Node, secrets []string) error {
	trimmed := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if v := strings.TrimSpace(s); v != "" {
			trimmed = append(trimmed, v)
		}
	}

	order := make([]int, len(nodes))
	for i := range nodes {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return nodes[order[i]].Name < nodes[order[j]].Name })

	for _, ni := range order {
		n := nodes[ni]

		fileNames := make([]string, 0, len(n.Files))
		for f := range n.Files {
			fileNames = append(fileNames, f)
		}
		sort.Strings(fileNames)

		for _, f := range fileNames {
			if err := gateFile(n.Name, f, n.Files[f], trimmed); err != nil {
				return err
			}
		}
	}

	return nil
}

// gateFile checks one file's content line by line, returning the first
// LeakError found or nil.
func gateFile(node, file, content string, secrets []string) error {
	path := node + "/" + file
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		for _, secret := range secrets {
			if strings.Contains(line, secret) {
				return &LeakError{File: path, Line: i + 1, Reason: "line contains a secret this node holds"}
			}
		}

		if m := secretKeyRe.FindStringSubmatch(line); m != nil && m[2] != redactedMarker {
			return &LeakError{File: path, Line: i + 1, Reason: fmt.Sprintf("line names a secret-bearing key (%s)", m[1])}
		}
	}

	return nil
}
