package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeManifest(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// The shipped example is the manifest every new operator starts from, so using it
// here checks two things at once: that --check-config accepts a good file, and
// that the example we ship is still one.
func exampleManifest(t *testing.T, mode os.FileMode) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "examples", "controller.yaml"))
	if err != nil {
		t.Fatalf("read the shipped example: %v", err)
	}
	return writeManifest(t, string(raw), mode)
}

// The whole point of the flag: a manifest the controller would refuse must be
// reported here instead of at startup, where the unit's Restart=on-failure turns
// the refusal into a crash loop of the control plane.
func TestCheckManifestRejectsWhatTheControllerWouldRefuse(t *testing.T) {
	p := writeManifest(t, "controller:\n  listen: [oops\n", 0o600)
	err := checkManifest(p)
	if err == nil {
		t.Fatal("a manifest that cannot be parsed was reported as valid")
	}
	if !errors.Is(err, errCheckFailed) {
		t.Fatalf("err = %v, want errCheckFailed so main does not log the report twice", err)
	}
}

func TestCheckManifestAcceptsAValidOne(t *testing.T) {
	if err := checkManifest(exampleManifest(t, 0o600)); err != nil {
		t.Fatalf("the shipped example manifest was rejected: %v", err)
	}
}

// A check that modifies the thing it checks is not a check. The startup path
// tightens the manifest to 0600; this one must not, or `--check-config` becomes a
// command with a side effect nobody expects.
func TestCheckManifestDoesNotTouchTheFile(t *testing.T) {
	p := exampleManifest(t, 0o644)
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkManifest(p); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() {
		t.Errorf("the check changed the file mode: %v -> %v", before.Mode(), after.Mode())
	}
}

func TestCheckManifestReportsAMissingFile(t *testing.T) {
	if err := checkManifest(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("a missing manifest was reported as valid")
	}
}
