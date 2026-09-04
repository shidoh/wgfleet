package reconcile

import (
	"context"
	"errors"
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
// runAllButTheExec applies everything except the command itself — modelling an
// `nft -f` that ran and FAILED, on every platform.
//
// It used to be runAll, which relied on the exec failing because "on a dev box nft
// does not exist". On a Linux CI runner or either stand VM, running as root,
// `nft -f` on `table ip x {}` SUCCEEDS: the marker is written, the assertion below
// fires, and the test leaves a stray `ip x` table in the host's kernel. A test whose
// verdict is a property of the machine — and which inverts on the platform the
// product actually ships to — is worse than no test.
func runAllButTheExec(actions []Action) {
	for _, a := range actions {
		if a.Kind != ActionExec && a.apply != nil && a.Changes() {
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
	runAllButTheExec(first) // the exec failed, so no marker is recorded

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
	runAllButTheExec(first)
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

// --- Task 1: check the ruleset before writing it, and keep a way back ---

// withNFTCheck swaps the ruleset checker for the duration of a test. The real one
// shells out to `nft -c`, which exists on a Linux node and not on a dev laptop, so
// a test that used it would render a different verdict per machine — the exact
// defect runAllButTheExec was written to remove.
func withNFTCheck(t *testing.T, f func(ruleset []byte) error) {
	t.Helper()
	prev := nftCheckRuleset
	nftCheckRuleset = f
	t.Cleanup(func() { nftCheckRuleset = prev })
}

// A ruleset the kernel would refuse must never reach the disk.
//
// Today the file is written FIRST and `nft -f` runs after, so a rejected ruleset
// leaves bad bytes on disk and an error that aborts the whole reconcile pass —
// which on the master means dockerfw, blocky, the VLESS inbound and both mihomo
// self-heals do not run, every 30 seconds, indefinitely. After a reboot the kernel
// has no table and the agent replays the same bad file forever.
func TestNFTApplyRefusesToWriteARulesetTheKernelWouldReject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.nft")
	withNFTCheck(t, func([]byte) error { return errors.New("syntax error, unexpected junk") })

	actions, err := NFTApply(path, []byte("table ip x { junk }\n"), func() bool { return true }, "apply")
	if err != nil {
		t.Fatalf("an invalid ruleset must not abort the pass, got: %v", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("the rejected ruleset was written to disk; a reboot would replay it")
	}
	summaries := nftSummaries(actions)
	if strings.Contains(summaries, string(ActionExec)) {
		t.Errorf("an invalid ruleset still scheduled an apply:\n%s", summaries)
	}
	if !strings.Contains(summaries, "syntax error") {
		t.Errorf("the plan does not say WHY the ruleset was refused:\n%s", summaries)
	}
}

// A valid ruleset must behave exactly as before the check existed.
func TestNFTApplyStillAppliesAValidRuleset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	withNFTCheck(t, func([]byte) error { return nil })

	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return true }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nftSummaries(actions), string(ActionExec)) {
		t.Errorf("a valid ruleset was not scheduled for apply:\n%s", nftSummaries(actions))
	}
}

// Being unable to CHECK is not the same as the ruleset being bad. On a box with no
// `nft` the checker cannot answer, and refusing to write there would leave every
// dev run and every non-Linux build reporting a broken firewall it never had.
// Same rule the drift probe follows: an unanswerable question changes nothing.
func TestNFTApplyProceedsWhenItCannotCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	withNFTCheck(t, func([]byte) error { return ErrNFTCheckUnavailable })

	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return true }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nftSummaries(actions), string(ActionExec)) {
		t.Errorf("an uncheckable ruleset was refused instead of applied:\n%s", nftSummaries(actions))
	}
}

// Replacing a ruleset must leave the one it REPLACED beside it, so there is
// something to go back to. The runbook for the netns flip says
// `nft -f /etc/wgfleet/wgfleet-master.nft.prev`; that file has to exist.
//
// Only a ruleset that was itself applied successfully may become .prev. The file
// on disk can also be bytes that were written and then REJECTED by the kernel,
// and preserving those as the way back hands the operator a broken ruleset. The
// discriminator is the applied-marker: it holds the digest of the last apply that
// actually succeeded.
func TestNFTApplyKeepsTheLastGoodRulesetAsPrev(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	withNFTCheck(t, func([]byte) error { return nil })
	first := []byte("table ip x {}\n")
	second := []byte("table ip x { chain c {} }\n")

	// Pass 1: write `first` and record it as successfully applied.
	a1, err := NFTApply(path, first, func() bool { return false }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(a1)
	if err := os.WriteFile(NFTAppliedMarker(path), []byte(digestOf(first)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pass 2: a different ruleset replaces it.
	a2, err := NFTApply(path, second, func() bool { return true }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(a2)

	prev, err := os.ReadFile(NFTPreviousRuleset(path))
	if err != nil {
		t.Fatalf("no .prev beside the ruleset, so the runbook rollback has nothing to load: %v", err)
	}
	if string(prev) != string(first) {
		t.Errorf(".prev holds %q, want the ruleset that was replaced (%q)", prev, first)
	}
}

// Bytes that were never confirmed applied must NOT become the way back.
func TestNFTApplyDoesNotPreserveAnUnappliedRulesetAsPrev(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.nft")
	withNFTCheck(t, func([]byte) error { return nil })
	// On disk but never applied: no marker beside it.
	if err := os.WriteFile(path, []byte("table ip stale {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return true }, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(actions)

	if _, err := os.Stat(NFTPreviousRuleset(path)); err == nil {
		t.Error("a ruleset that was never applied was preserved as the rollback target")
	}
}
