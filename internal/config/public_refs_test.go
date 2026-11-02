package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// lessonRef matches a numbered pointer into the maintainer's private lessons file
// ("an earlier finding", "an earlier finding:", "an earlier finding", "an earlier finding"), including one
// wrapped across a comment line break.
var lessonRef = regexp.MustCompile(`(?i)\blessons?\b[\s/]*-?\s*#?\s*\d`)

// maxScannedSize skips anything larger than a source file could plausibly be.
const maxScannedSize = 2 << 20

// The lessons file is not part of the repository, so a "lesson #NN" anywhere in
// the source is a citation nobody outside can follow. The reason belongs inline.
func TestSourceHasNoLessonReferences(t *testing.T) {
	roots := []string{"cmd", "internal", "deploy", "docs", "tools", "test", "proto", ".github"}
	var files []string
	for _, r := range roots {
		err := filepath.WalkDir(filepath.Join(repoRoot, r), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("walk %s: %v", r, err)
		}
	}
	top, err := filepath.Glob(filepath.Join(repoRoot, "*"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, top...)

	for _, p := range files {
		switch filepath.Ext(p) {
		case ".go", ".md", ".sh", ".yaml", ".yml", ".json", ".service", ".proto", "":
		default:
			continue
		}
		if strings.HasSuffix(p, "public_refs_test.go") || strings.Contains(p, "/docs/adr/") {
			continue // this guard's own pattern; ADRs are local-only
		}
		info, err := os.Stat(p)
		if err != nil || info.IsDir() || info.Size() > maxScannedSize {
			continue // built binaries sit in the root untracked; sources are small
		}
		body, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("read %s: %v", p, err)
			continue
		}
		for _, loc := range lessonRef.FindAllIndex(body, -1) {
			line := strings.Count(string(body[:loc[0]]), "\n") + 1
			t.Errorf("%s:%d cites the private lessons file: %q", p, line, body[loc[0]:loc[1]])
		}
	}
}
