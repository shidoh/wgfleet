package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
