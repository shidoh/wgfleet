package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDigestFileChangesWithContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := DigestFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// A comment-only edit must still register: an operator who changed something
	// and did not apply it wants to be told, whatever they changed.
	if err := os.WriteFile(p, []byte("a # note"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := DigestFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("the digest ignored a change to the file")
	}
}

// The record is what lets a SEPARATE process — a support bundle, a --check-config
// run — answer "what is the controller running on" without asking the controller.
func TestEffectiveRecordRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "controller.effective")
	if err := WriteEffective(p, "abc123", time.Now()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := ReadEffectiveDigest(p); got != "abc123" {
		t.Fatalf("ReadEffectiveDigest = %q, want abc123", got)
	}
}

// No record must read as "unknown", never as a digest that happens to match or
// mismatch — the caller decides what to do with silence.
func TestEffectiveRecordAbsentReadsEmpty(t *testing.T) {
	if got := ReadEffectiveDigest(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Fatalf("ReadEffectiveDigest on a missing record = %q, want empty", got)
	}
}
