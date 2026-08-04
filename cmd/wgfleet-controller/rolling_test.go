package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeAgentBin writes a stub `wgfleet-agent` that reports ver/commit and appends a
// line to a counter file each time it runs, so a test can tell a cache hit from a
// re-exec.
func fakeAgentBin(t *testing.T, dir, ver, commit, counter string) string {
	t.Helper()
	bin := filepath.Join(dir, "wgfleet-agent")
	script := "#!/bin/sh\n" +
		"echo run >> " + counter + "\n" +
		"echo 'wgfleet-agent " + ver + " (commit " + commit + ", built 2026-07-27T10:35:22Z, go1.26.5)'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake agent: %v", err)
	}
	return bin
}

func runCount(t *testing.T, counter string) int {
	t.Helper()
	b, err := os.ReadFile(counter)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return len(strings.Fields(string(b)))
}

// The dashboard polls the rollout panel every 2-15s, and every open tab polls
// independently. Re-execing a 28 MB binary on each poll is pure waste, so the
// probe is cached — but a binary redeployed under a running controller must be
// picked up without a restart, which is what makes size+mtime the cache key
// rather than "probe once at startup".
func TestAgentBinVersionCachesUntilTheBinaryChanges(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "runs")
	bin := fakeAgentBin(t, dir, "v0.1.5-8-g3ae9df0", "3ae9df0", counter)

	c := &agentBinVersion{path: bin}
	ctx := context.Background()

	first, err := c.get(ctx)
	if err != nil {
		t.Fatalf("first probe: %v", err)
	}
	if first == "" {
		t.Fatal("first probe returned an empty version")
	}
	for i := 0; i < 5; i++ {
		got, err := c.get(ctx)
		if err != nil || got != first {
			t.Fatalf("cached probe %d = (%q, %v), want (%q, nil)", i, got, err, first)
		}
	}
	if n := runCount(t, counter); n != 1 {
		t.Errorf("binary executed %d times across 6 calls, want 1 — the probe is not cached", n)
	}

	// Redeploy a different build over the same path, as deploy-master.sh does.
	time.Sleep(10 * time.Millisecond) // ensure a distinct mtime
	_ = fakeAgentBin(t, dir, "v0.1.6-14-g2b42a3f", "2b42a3f", counter)

	second, err := c.get(ctx)
	if err != nil {
		t.Fatalf("probe after redeploy: %v", err)
	}
	if second == first {
		t.Errorf("version still %q after the binary was replaced — the cache did not invalidate", second)
	}
	if !strings.Contains(second, "2b42a3f") {
		t.Errorf("version = %q, want it to reflect the new binary", second)
	}
}

// An unset agent_bin must be an error, not an empty version: an empty want would
// make BuildPlan treat every node as outdated and offer a roll that installs
// nothing.
func TestAgentBinVersionRejectsAnUnconfiguredPath(t *testing.T) {
	c := &agentBinVersion{path: ""}
	got, err := c.get(context.Background())
	if err == nil {
		t.Fatalf("expected an error for an unconfigured binary, got %q", got)
	}
	if !strings.Contains(err.Error(), "agent_bin") {
		t.Errorf("error %q does not name the setting the operator must fix", err)
	}
}

func TestAgentBinVersionReportsAMissingBinary(t *testing.T) {
	c := &agentBinVersion{path: filepath.Join(t.TempDir(), "absent")}
	if got, err := c.get(context.Background()); err == nil {
		t.Fatalf("expected an error for a missing binary, got %q", got)
	}
}
