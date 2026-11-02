package support

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// secretKeyRe matches a line whose KEY names it as secret-bearing, in
// `key: value`, `key = value`, `key=value`, or JSON `"key": "value"` form.
// Used by both Scrub (mask) and Gate (refuse) — it is the coarse layer, for
// uncontrolled text such as container logs where we do not control the
// format.
//
// The optional `["']?` around the separator absorbs a JSON key's closing
// quote (`"secret":`) and a JSON value's surrounding quotes (`"secret":
// "value"`) without requiring them — a bare `key: value` line still matches.
// Without this, `\bsecret\b\s*[:=]` never matches `"secret":` because a
// closing quote sits between the key and the colon, and a JSON-configured
// collector's log line (xray, for one — see Task 3's containers.txt) sails
// through ungated.
//
// The value group (2) is lazy but anchored to end-of-line with `(?m)$` and a
// trailing `["']?\s*` so it still captures the ENTIRE value — including a
// multi-word secret, and past its own closing quote and any trailing
// punctuation — while stripping a matched wrapping quote where one is
// present. ("." does not match "\n" in Go's RE2 without the "s" flag, so
// this stays bounded to one line regardless.) This was `\S+` originally,
// which only caught the first whitespace-delimited token of a multi-word
// secret (e.g. "Authorization: Bearer <jwt>" masked only "Bearer", leaving
// the token itself in plain sight). Over-masking trailing prose or
// punctuation on a matched line is the correct tradeoff here: under-masking
// leaks a secret, over-masking only costs readability, and this is
// explicitly the layer for text whose format we do not control. Sharing
// this regex also keeps Scrub and Gate consistent by construction — Gate
// cannot fire on a line Scrub already fully redacted.
// Three things this pattern got wrong for a long time, each of which leaked:
//
//   - The separator class was [_-]? , so it matched "private_key" and
//     "private-key" but NOT "private key" — which is exactly how `wg`/`awg show`
//     and most WireGuard tooling spell it.
//   - It was anchored with a leading \b, and "_" is a word character, so
//     "fleet_secret", "admin_password", "ca_key" and "awg3_key" had no boundary
//     before the matched word and sailed through untouched. A leading name part
//     is now consumed instead of required to be absent.
//   - It knew nothing of "header protection key". `awg show` deliberately prints
//     "private key: (hidden)" and this file's own comment cites that as proof the
//     command is safe to collect — but it prints the AmneziaWG 3.x header
//     protection key IN FULL, so it must be masked. Also added:
//     psk, uuid, passphrase, and a bare "key" term reached through the name
//     prefix, which is what catches awg3_key, ca_key and anything else this
//     project names that way without listing each one.
//
// Over-masking trailing prose is the correct trade here and always was: it costs
// readability, and the alternative costs a secret.
var secretKeyRe = regexp.MustCompile(`(?im)[\w.-]*(private[_\s-]?key|pre[_\s-]?shared[_\s-]?key|preshared[_\s-]?key|header[_\s-]?protection[_\s-]?key|secret|password|passwd|passphrase|token|authorization|psk|uuid|key)["']?\s*[:=]\s*["']?(.+?)["']?\s*$`)

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
//  1. Exact — every value in secrets is searched for verbatim, over the whole
//     of each field's content rather than one line at a time, so a secret
//     that itself spans multiple lines (a PEM-encoded key, wrapped at 64
//     columns) is still found. The node holds its own real keys, so this is
//     precise and has no false positives. It is the primary check because
//     AmneziaWG public and private keys share a shape and no regex can tell
//     them apart.
//  2. By key name — for a secret this process does not know about, arriving in
//     uncontrolled text.
//
// Empty or whitespace-only entries in secrets are skipped: strings.Contains with
// an empty needle is always true, and one such entry would fail every bundle.
//
// Files are walked in sorted name order (nodes by Name, then files by name
// within each node) so the first hit reported is deterministic. Each node's
// ManifestEntry.Cmd and .Err are checked too — renderManifest (Task 1) writes
// both into MANIFEST.txt, and a failing collector's error text can carry
// command output, so it is not safe to gate Files and leave the manifest
// ungated.
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
			if err := gateContent(n.Name+"/"+f, n.Files[f], trimmed); err != nil {
				return err
			}
		}

		manifestPath := n.Name + "/MANIFEST.txt"
		for _, e := range n.Entries {
			if err := gateContent(manifestPath, e.Cmd, trimmed); err != nil {
				return err
			}
			if err := gateContent(manifestPath, e.Err, trimmed); err != nil {
				return err
			}
		}
	}

	return nil
}

// gateContent checks one field's content, returning the first LeakError found
// or nil. path identifies where the content will land in the archive (a
// collected file, or the manifest for entry Cmd/Err text).
//
// The exact-match check (secrets) runs over the WHOLE content, not line by
// line: a needle that itself contains a newline — the fleet CA private key
// and every exit's SSH bootstrap key are both PEM, which pem.EncodeToMemory
// wraps at 64 columns — can never be a substring of any single line, so a
// per-line strings.Contains can never find it. strings.Index over the full
// string finds it regardless of how many lines it spans; the byte offset is
// then converted back to a 1-based line number (counting newlines before the
// match start) purely for a useful LeakError, not for detection. When more
// than one secret matches, the earliest occurrence in the content is
// reported, matching what a line-by-line scan would have found first.
//
// This deliberately does NOT split secrets into line-sized fragments and
// search for those independently: a short fragment shared with ordinary text
// (a PEM's "-----BEGIN...-----" banner line, say) would then flag content
// that never actually contained the secret, trading a false negative for a
// false positive rather than fixing the real gap.
//
// The secret-bearing-key-name regex stays line-by-line: it is a single-line
// pattern by construction (Go's RE2 "." does not match "\n" without the "s"
// flag), so a per-line scan already finds every match it can find.
func gateContent(path, content string, secrets []string) error {
	bestIdx := -1
	for _, secret := range secrets {
		if idx := strings.Index(content, secret); idx >= 0 && (bestIdx == -1 || idx < bestIdx) {
			bestIdx = idx
		}
	}
	if bestIdx >= 0 {
		line := strings.Count(content[:bestIdx], "\n") + 1
		return &LeakError{File: path, Line: line, Reason: "line contains a secret this node holds"}
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if m := secretKeyRe.FindStringSubmatch(line); m != nil && m[2] != redactedMarker {
			return &LeakError{File: path, Line: i + 1, Reason: fmt.Sprintf("line names a secret-bearing key (%s)", m[1])}
		}
	}

	return nil
}
