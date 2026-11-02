package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// internalRefs matches cross-references that only resolve inside the source
// repository: ADR numbers, "lesson #NN" in any punctuation, and docs/ paths.
var internalRefs = regexp.MustCompile(`ADR[- ]?\d{3,4}|lessons?[ -]?#\s*\d+|docs/(adr|DESIGN|lessons|research|plans)`)

// repoRoot is this package's path relative to the repository root.
const repoRoot = "../.."

// Beta testers receive ONLY the release tarball — the repository is private — so an
// "(ADR-0021)" or a lesson number in a shipped file is a pointer to something they
// cannot open. It reads as a citation and delivers nothing. Where such a reference
// was the sole justification for a non-obvious default, the reason belongs inline.
//
// The file list is parsed out of the Makefile's release-archive recipe rather than
// hardcoded, so adding a file to the archive automatically brings it under this
// rule — which is the failure mode worth guarding: not the files we remembered,
// but the next one somebody packs.
func TestShippedDocsHaveNoInternalReferences(t *testing.T) {
	shipped := shippedFiles(t)
	if len(shipped) < 5 {
		t.Fatalf("parsed only %d shipped files from the Makefile; the recipe format probably changed", len(shipped))
	}
	for _, rel := range shipped {
		// .json is in the list because grafana-dashboard.json is the most-referenced
		// file in the archive and carried ten ADR citations plus a lesson number in its
		// panel titles and descriptions. It was skipped for being an extension nobody
		// thought of, which is precisely the shape of failure this test exists to catch:
		// not the files we remembered, but the next one somebody packs.
		switch filepath.Ext(rel) {
		case ".md", ".yaml", ".yml", ".sh", ".service", ".json":
		default:
			continue // binaries and generated files
		}
		body, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Errorf("shipped file %s is unreadable: %v", rel, err)
			continue
		}
		for i, line := range strings.Split(string(body), "\n") {
			if m := internalRefs.FindString(line); m != "" {
				t.Errorf("%s:%d ships an internal-only reference %q — testers have no repo access; inline the reason instead\n    %s",
					rel, i+1, m, strings.TrimSpace(line))
			}
		}
	}
}

// shippedFiles returns the repo-relative source paths the release-archive target
// copies into the tarball.
func shippedFiles(t *testing.T) []string {
	t.Helper()
	mk, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	inTarget := false
	var out []string
	for _, line := range strings.Split(string(mk), "\n") {
		switch {
		case strings.HasPrefix(line, "release-archive:"):
			inTarget = true
			continue
		case inTarget && line != "" && !strings.HasPrefix(line, "\t"):
			inTarget = false // dedented: next target
		}
		if !inTarget {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "@")))
		if len(fields) < 3 || fields[0] != "cp" {
			continue
		}
		// Every argument but the destination is a source path; skip $(DIST)-rooted
		// ones (binaries staged by an earlier build step, not repo files).
		for _, src := range fields[1 : len(fields)-1] {
			if strings.Contains(src, "$(") {
				continue
			}
			// The recipe uses shell globs (deploy/systemd/*.service); expand them so
			// each real file is checked rather than a path that cannot be opened.
			if strings.ContainsAny(src, "*?[") {
				matches, err := filepath.Glob(filepath.Join(repoRoot, src))
				if err != nil {
					t.Fatalf("bad glob %q in Makefile: %v", src, err)
				}
				for _, m := range matches {
					rel, err := filepath.Rel(repoRoot, m)
					if err != nil {
						t.Fatalf("relativize %q: %v", m, err)
					}
					out = append(out, rel)
				}
				continue
			}
			out = append(out, src)
		}
	}
	return out
}

// Every intra-doc link in a shipped document must resolve INSIDE the archive.
//
// The docs link each other by repo name (docs/cli.md); the release target renames
// them on the way in (CLI.md). On a case-sensitive filesystem — every server these
// ship to — that left 16 dead links, the first of them on the first page a tester
// opens, and six more pointed at documents the archive did not carry at all. The
// Makefile now rewrites the names and ships the missing files; this is what keeps
// the two halves from drifting apart again.
func TestShippedDocsLinkOnlyToShippedDocs(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	// Parse the release target's copies: repo path -> archive name.
	shipped := map[string]string{} // repo path (e.g. docs/cli.md) -> CLI.md
	archive := map[string]bool{}   // names present in the archive
	cp := regexp.MustCompile(`(?m)^\tcp (\S+\.md)\s+\$\(DIST\)/\$\(PKG\)/(\S+)$`)
	for _, m := range cp.FindAllStringSubmatch(string(mk), -1) {
		shipped[m[1]] = m[2]
		archive[m[2]] = true
	}
	if len(shipped) < 8 {
		t.Fatalf("parsed only %d shipped docs from the Makefile; the parser has drifted", len(shipped))
	}
	// Everything ELSE the archive carries, so a link to a shipped manifest or script
	// can be resolved too. `cp a b dir/` puts each source under its own basename.
	// Sources and destination are aligned with runs of spaces in the Makefile, so
	// the separator is a run of blanks, not a single space: with a single space every
	// directory copy silently failed to parse and nothing under examples/,
	// systemd/ or assets/ was ever considered shipped.
	dirCp := regexp.MustCompile(`(?m)^\tcp ((?:\S+[ \t]+)+)\$\(DIST\)/\$\(PKG\)/(\S*/)$`)
	for _, m := range dirCp.FindAllStringSubmatch(string(mk), -1) {
		for _, src := range strings.Fields(m[1]) {
			matches, _ := filepath.Glob(filepath.Join("..", "..", src))
			if len(matches) == 0 {
				matches = []string{src}
			}
			for _, mt := range matches {
				archive[m[2]+filepath.Base(mt)] = true
			}
		}
	}

	// Every relative link, not only the .md ones. The first version of this regex
	// ended in `\.md`, so three links pointing at ../deploy/examples/*.yaml — the
	// manifests the docs tell a tester to copy — were never examined at all, and
	// resolved from inside the package to a path ABOVE the archive root.
	link := regexp.MustCompile(`\]\(([^)#][^)]*)\)`)
	for repoPath, archiveName := range shipped {
		body, err := os.ReadFile(filepath.Join("..", "..", repoPath))
		if err != nil {
			t.Errorf("%s is listed in the release archive but not in the repo: %v", repoPath, err)
			continue
		}
		for _, m := range link.FindAllStringSubmatch(string(body), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			// A fragment addresses a heading INSIDE the target file; the file is
			// what has to ship, and the Makefile's fixlinks rewrites the name and
			// leaves the fragment alone. Without this, every `configuration.md#key`
			// link read as a filename that exists nowhere.
			file := target
			if i := strings.Index(file, "#"); i >= 0 {
				file = file[:i]
			}
			base := strings.TrimLeft(strings.ReplaceAll(file, "./", ""), "./")
			base = strings.TrimPrefix(base, "docs/")
			// The Makefile's fixlinks rewrites repo paths to the names the archive
			// uses; mirror the one class that is not a plain rename, so the check
			// measures the archive as built rather than the source as written.
			if i := strings.Index(base, "deploy/examples/"); i >= 0 {
				base = "examples/" + filepath.Base(base)
			}
			// A link may already name the ARCHIVE path (examples/RU-SPLIT-TUNNEL.md),
			// which is correct as written and needs no rewrite.
			if archive[base] {
				continue
			}
			// Otherwise it names a repo doc, and the Makefile's rewrite turns it into
			// the archive name below.
			renamed, isShipped := shipped["docs/"+base]
			if !isShipped {
				renamed, isShipped = shipped[base]
			}
			if !isShipped {
				// Not a doc the archive carries under a renamed form; it must at least
				// exist in the repo, or the link is dead everywhere.
				if _, err := os.Stat(filepath.Join("..", "..", "docs", base)); err != nil {
					if _, err2 := os.Stat(filepath.Join("..", "..", base)); err2 != nil {
						t.Errorf("%s links %q, which exists nowhere", repoPath, target)
					}
				}
				t.Errorf("%s (ships as %s) links %q, which the release archive does not carry — "+
					"either add it to release-archive or stop linking it from a shipped document",
					repoPath, archiveName, target)
				continue
			}
			if !archive[renamed] {
				t.Errorf("%s links %q which maps to %q, absent from the archive", repoPath, target, renamed)
			}
		}
	}
}
