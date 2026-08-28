package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nftSummaries(actions []Action) string {
	var b strings.Builder
	for _, a := range actions {
		b.WriteString(string(a.Kind) + " " + a.Summary + "\n")
	}
	return b.String()
}

// runAll applies every changing action. On a dev box `nft` does not exist, so the
// exec genuinely fails — which is the case under test: a failed apply must leave
// the marker unwritten.
func runAll(actions []Action) {
	for _, a := range actions {
		if a.apply != nil && a.Changes() {
			_ = a.apply(context.Background())
		}
	}
}

// A FAILED `nft -f` must be retried, not mistaken for done.
//
// `nft -f` is atomic, so a failure leaves the OLD table in the kernel while the new
// bytes are already on disk. Gating the next pass on "did the FILE change" then
// reports "already loaded" forever: disk says one thing, the kernel runs another,
// and the node reports Ready while running rules nobody wrote.
func TestNFTApplyRetriesAfterAFailedApply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	ruleset := []byte("table ip x {}\n")
	// A table IS present in the kernel — the stale one the failed apply did not replace.
	loaded := func() bool { return true }

	first, err := NFTApply(path, ruleset, loaded, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAll(first) // the exec fails here (no nft on this box), so no marker is recorded

	if _, err := os.Stat(NFTAppliedMarker(path)); err == nil {
		t.Fatal("a failed apply recorded itself as successful")
	}

	second, err := NFTApply(path, ruleset, loaded, "apply")
	if err != nil {
		t.Fatal(err)
	}
	var retries bool
	for _, a := range second {
		if a.Kind == ActionExec && a.Changes() {
			retries = true
		}
	}
	if !retries {
		t.Fatalf("the failed apply was mistaken for done:\n%s", nftSummaries(second))
	}
}

// Once an apply has actually succeeded and the table is present, the pass is quiet.
func TestNFTApplyIsQuietOnceAppliedAndPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	ruleset := []byte("table ip x {}\n")

	first, err := NFTApply(path, ruleset, func() bool { return true }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range first {
		if a.Kind != ActionExec && a.apply != nil && a.Changes() {
			if err := a.apply(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Stand in for the exec succeeding, which is all OnApplied does.
	if err := os.WriteFile(NFTAppliedMarker(path), []byte(digestOf(ruleset)), 0o644); err != nil {
		t.Fatal(err)
	}

	second, err := NFTApply(path, ruleset, func() bool { return true }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range second {
		if a.Changes() {
			t.Errorf("steady state must be quiet, got %q", a.Summary)
		}
	}
}

// A reboot clears nft state without touching either file, so presence in the
// kernel has to be checked as well as the marker: they answer different questions.
func TestNFTApplyRepairsAMissingKernelTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	ruleset := []byte("table ip x {}\n")
	if err := os.WriteFile(path, ruleset, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(NFTAppliedMarker(path), []byte(digestOf(ruleset)), 0o644); err != nil {
		t.Fatal(err)
	}

	actions, err := NFTApply(path, ruleset, func() bool { return false }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nftSummaries(actions), "kernel table missing") {
		t.Errorf("no self-heal when the kernel lost the table:\n%s", nftSummaries(actions))
	}
}
