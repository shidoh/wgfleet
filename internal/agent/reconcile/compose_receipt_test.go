package reconcile

import (
	"context"
	"path/filepath"
	"testing"
)

// A compose file on disk says what SHOULD run, not what does: the `up -d` that
// was meant to apply it can be killed (an agent restart mid-pass) or fail (an
// image that will not pull). The receipt is the only record that it succeeded.
func TestComposeAppliedNeedsAReceiptForThatExactFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "docker-compose.yml")
	rendered := []byte("services: {mihomo: {image: metacubex/mihomo:v1.19.33}}\n")

	if ComposeApplied(file, rendered) {
		t.Fatal("no receipt yet, but the file reads as applied")
	}
	recordComposeApplied(file, rendered)
	if !ComposeApplied(file, rendered) {
		t.Fatal("a receipt for this exact file does not count as applied")
	}
	if ComposeApplied(file, []byte("services: {mihomo: {image: metacubex/mihomo:v1.19.34}}\n")) {
		t.Fatal("a receipt for an older file counts as applied for a newer one")
	}
}

// The receipt is written only when `up -d` itself succeeded: a failed bring-up
// must leave the next pass wanting to retry it.
func TestComposeUpActionRecordsTheReceiptOnlyOnSuccess(t *testing.T) {
	file := filepath.Join(t.TempDir(), "docker-compose.yml")
	rendered := []byte("services: {}\n")

	up := ComposeUpAction("bring the stack up", file, rendered)
	if up.Kind != ActionExec || up.Display != "docker compose -f "+file+" up -d" {
		t.Fatalf("unexpected action: kind=%q display=%q", up.Kind, up.Display)
	}

	withComposeBin(t, "false") // the up -d fails
	if err := ComposeUpAction("bring the stack up", file, rendered).apply(context.Background()); err == nil {
		t.Fatal("the failing command did not surface")
	}
	if ComposeApplied(file, rendered) {
		t.Fatal("a failed up -d left a receipt")
	}

	withComposeBin(t, "true") // the up -d succeeds
	if err := ComposeUpAction("bring the stack up", file, rendered).apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !ComposeApplied(file, rendered) {
		t.Fatal("a successful up -d left no receipt")
	}
}

func withComposeBin(t *testing.T, bin string) {
	t.Helper()
	prev := composeBin
	composeBin = bin
	t.Cleanup(func() { composeBin = prev })
}
