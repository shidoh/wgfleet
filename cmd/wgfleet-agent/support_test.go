package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// End-to-end on this machine: the bundle must be produced, be a real gzip, and
// carry a manifest. Collectors will mostly fail in a test environment — that is
// the point of recording failures rather than aborting.
func TestSupportBundleWritesAnArchive(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := writeSupportBundle(context.Background(), supportOpts{
		Out: out, Node: "test-node", Role: "exit", Note: "written by a test",
	}); err != nil {
		t.Fatalf("writeSupportBundle: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Error("output is not gzip")
	}
}

// The gate must run on the real path, not only in unit tests: a bundle whose
// secrets are checked nowhere is the failure this feature is built to prevent.
func TestSupportBundleRefusesWhenASecretWouldLeak(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	err := writeSupportBundle(context.Background(), supportOpts{
		Out: out, Node: "test-node", Role: "exit",
		// A collector that emits a value the node declares secret.
		extra:   []supportSection{{File: "state.txt", Name: "injected", Body: "PrivateKey = " + testSecret}},
		Secrets: []string{testSecret},
	})
	if err == nil {
		t.Fatal("bundle was written despite containing a declared secret")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Error("the error printed the secret")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("an archive was left on disk after the gate refused")
	}
}

const testSecret = "aFakeButWellFormedPrivateKeyForTests1234567="

// Regression pin for a CRITICAL found in review: --note is free-form text a
// tester types describing what went wrong (the single likeliest place someone
// pastes a key without realising it), and the first version of writeSupportBundle
// embedded it into MANIFEST.txt with NO Scrub and NO Gate — it never touched
// node.Files, the only structure either one inspects. This note deliberately has
// no "key:"/"key=" shape (prose, not a config line), so Scrub's key-name regex
// cannot catch it either; only Gate's exact-secret-match layer can, which is
// exactly what the fix wires up.
func TestSupportBundleGatesTheNoteField(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	err := writeSupportBundle(context.Background(), supportOpts{
		Out: out, Node: "test-node", Role: "exit",
		Note:    "it broke, here is my key " + testSecret,
		Secrets: []string{testSecret},
	})
	if err == nil {
		t.Fatal("bundle was written despite a secret pasted into --note")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatal("the error printed the secret")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("an archive was left on disk after the gate refused the note")
	}
}

// Same regression, the other direction: a note with no secret in it must still
// reach the archive, and reach it byte-identical to what MANIFEST.txt actually
// carries — the fix must not over-block or silently drop harmless notes. Reads
// back through gzip+tar rather than grepping the raw file: the archive is
// compressed, so a raw-byte search would find nothing and look like a pass
// whether or not the note actually made it in (a prior manual check made
// exactly that mistake against the raw file).
func TestSupportBundleWritesAHarmlessNoteVerbatim(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	const note = "reconcile loop keeps erroring on the wgcf planner"
	if err := writeSupportBundle(context.Background(), supportOpts{
		Out: out, Node: "test-node", Role: "exit", Note: note,
	}); err != nil {
		t.Fatalf("writeSupportBundle: %v", err)
	}
	manifest := readTarEntry(t, out, "MANIFEST.txt")
	if !strings.Contains(manifest, note) {
		t.Fatalf("MANIFEST.txt did not carry the note verbatim:\n%s", manifest)
	}
}

// readTarEntry decompresses a gzip+tar archive and returns one entry's content
// as a string, failing the test if the archive or the entry cannot be read.
func readTarEntry(t *testing.T, archivePath, name string) string {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatalf("archive has no entry %q", name)
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if hdr.Name != name {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(body)
	}
}

// Regression pin for the grandchild-kill fix (found live: exec.CommandContext's
// default Cancel only signals the immediate `sh`, so a compound shell command
// left its child running — and holding stdout/stderr open — well past the
// deadline; a first attempt at this measured `sleep 30 && echo done` taking the
// full 30s despite a 10s timeout). Uses the injectable per-call timeout so this
// runs in well under a second instead of waiting out the real production bound.
func TestExecRunnerKillsTheWholeProcessGroupOnTimeout(t *testing.T) {
	r := execRunner{timeout: 100 * time.Millisecond}
	start := time.Now()
	// sh forks a CHILD to run `sleep` here (the compound "&&" prevents sh from
	// exec'ing straight into it), so this only proves the fix if the whole
	// process GROUP is killed, not just sh itself.
	_, err := r.Run(context.Background(), "sleep 5 && echo done")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got: %v", err)
	}
	// supportCommandWaitDelay (2s) is the backstop if the group-kill fails to
	// actually stop the process; well under that confirms the kill itself
	// worked, not just the backstop papering over a regression.
	if elapsed >= time.Second {
		t.Fatalf("command was not cut off promptly: took %s (regression: only sh was killed, not its process group)", elapsed)
	}
}
