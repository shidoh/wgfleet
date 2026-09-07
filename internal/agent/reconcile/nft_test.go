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

	first, err := NFTApply(path, ruleset, loaded, nil, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(first) // the exec failed, so no marker is recorded

	if _, err := os.Stat(NFTAppliedMarker(path)); err == nil {
		t.Fatal("a failed apply recorded itself as successful")
	}

	second, err := NFTApply(path, ruleset, loaded, nil, "apply")
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

	first, err := NFTApply(path, ruleset, func() bool { return true }, nil, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(first)
	// Stand in for the exec succeeding, which is all OnApplied does.
	if err := os.WriteFile(NFTAppliedMarker(path), []byte(digestOf(ruleset)), 0o644); err != nil {
		t.Fatal(err)
	}

	second, err := NFTApply(path, ruleset, func() bool { return true }, nil, "apply")
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

	actions, err := NFTApply(path, ruleset, func() bool { return false }, nil, "apply")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nftSummaries(actions), "kernel table missing") {
		t.Errorf("no self-heal when the kernel lost the table:\n%s", nftSummaries(actions))
	}
}

// --- Task 1: check the ruleset before writing it, and keep a way back ---

// checkerFor returns a stub ruleset checker. The real one shells out to `nft -c`,
// which exists on a Linux node and not on a dev laptop, so a test that used it
// would render a different verdict per machine — the exact defect
// runAllButTheExec was written to remove.
func checkerFor(err error) func([]byte) error {
	return func([]byte) error { return err }
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
	checker := checkerFor(errors.New("syntax error, unexpected junk"))

	actions, err := NFTApply(path, []byte("table ip x { junk }\n"), func() bool { return true }, checker, "apply")
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
	checker := checkerFor(nil)

	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return true }, checker, "apply")
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
	checker := checkerFor(ErrNFTCheckUnavailable)

	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return true }, checker, "apply")
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
	checker := checkerFor(nil)
	first := []byte("table ip x {}\n")
	second := []byte("table ip x { chain c {} }\n")

	// Pass 1: write `first` and record it as successfully applied.
	a1, err := NFTApply(path, first, func() bool { return false }, checker, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(a1)
	if err := os.WriteFile(NFTAppliedMarker(path), []byte(digestOf(first)), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pass 2: a different ruleset replaces it.
	a2, err := NFTApply(path, second, func() bool { return true }, checker, "apply")
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
	checker := checkerFor(nil)
	// On disk but never applied: no marker beside it.
	if err := os.WriteFile(path, []byte("table ip stale {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return true }, checker, "apply")
	if err != nil {
		t.Fatal(err)
	}
	runAllButTheExec(actions)

	if _, err := os.Stat(NFTPreviousRuleset(path)); err == nil {
		t.Error("a ruleset that was never applied was preserved as the rollback target")
	}
}

// fakeNFT puts an `nft` of our own on PATH. Without it this whole class is
// unprovable on a dev Mac, which is exactly how it shipped: the check calls a
// real `nft`, macOS has none, so the branch under test never runs and the suite
// is green while the same code refuses every ruleset on a Linux runner.
func fakeNFT(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// An `nft` that cannot answer must not be read as "the ruleset is bad".
//
// `nft -c` opens a netlink socket to resolve a ruleset, so without CAP_NET_ADMIN
// it fails on EVERY input with "cache initialization failed". Taking that for a
// rejection stops the agent writing any ruleset at all — and quietly, because a
// refusal is a no-change entry: the pass stays green, drift stays zero, and the
// firewall never converges. Seen on the v0.2.2 release runner, where it failed
// 20 tests across four packages.
func TestARulesetIsWrittenWhenNFTCannotCheckAnything(t *testing.T) {
	fakeNFT(t, "#!/bin/sh\necho 'netlink: Error: cache initialization failed: Operation not permitted' >&2\nexit 1\n")

	path := filepath.Join(t.TempDir(), "rules.nft")
	actions, err := NFTApply(path, []byte("table ip x {}\n"), func() bool { return false }, nil, "apply")
	if err != nil {
		t.Fatal(err)
	}
	summaries := nftSummaries(actions)
	if strings.Contains(summaries, "refusing") {
		t.Fatalf("an unusable checker was mistaken for a verdict:\n%s", summaries)
	}
	var writes, execs bool
	for _, a := range actions {
		if !a.Changes() {
			continue
		}
		if a.Kind == ActionExec {
			execs = true
		} else {
			writes = true
		}
	}
	if !writes || !execs {
		t.Fatalf("the ruleset must still be written and applied:\n%s", summaries)
	}
}

// The other half of the same question: a checker that CAN answer is still obeyed.
// Without this, "treat a failure as unavailable" would pass by refusing nothing,
// ever — and the pre-check would be decoration.
func TestARulesetNFTActuallyRejectsIsStillRefused(t *testing.T) {
	fakeNFT(t, "#!/bin/sh\nfor a in \"$@\"; do f=\"$a\"; done\n"+
		"grep -q wgfleet_nft_check_probe \"$f\" && exit 0\n"+
		"echo 'ruleset:1:1-5: Error: syntax error, unexpected junk' >&2\nexit 1\n")

	path := filepath.Join(t.TempDir(), "rules.nft")
	actions, err := NFTApply(path, []byte("junk\n"), func() bool { return false }, nil, "apply")
	if err != nil {
		t.Fatal(err)
	}
	summaries := nftSummaries(actions)
	if !strings.Contains(summaries, "refusing") {
		t.Fatalf("a ruleset nft rejects must not be written:\n%s", summaries)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("a refused ruleset reached the disk")
	}
	// Refused is not converged: the previous ruleset stays in the kernel, and the
	// component says so by failing rather than by a NoChange line nobody reads.
	if len(actions) != 1 || actions[0].apply(context.Background()) == nil {
		t.Fatalf("a refused ruleset must fail its component:\n%s", summaries)
	}
}

// Symbolic priorities are hook-specific on nftables 1.0.2. The check is static
// so it holds on a box whose own nft would have accepted the ruleset.
func TestCheckNFTPortabilityRefusesHookSpecificNamesElsewhere(t *testing.T) {
	good := "table ip t {\n\tchain a {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t}\n" +
		"\tchain b {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t}\n" +
		"\tchain c {\n\t\ttype filter hook postrouting priority srcnat + 10; policy accept;\n\t}\n" +
		"\tchain d {\n\t\ttype nat hook output priority -100; policy accept;\n\t}\n" +
		"\tchain e {\n\t\ttype filter hook output priority mangle; policy accept;\n\t}\n}\n"
	if err := CheckNFTPortability([]byte(good)); err != nil {
		t.Fatalf("a portable ruleset was refused: %v", err)
	}
	bad := "table ip t {\n\tchain d {\n\t\ttype nat hook output priority dstnat; policy accept;\n\t}\n}\n"
	if err := CheckNFTPortability([]byte(bad)); err == nil {
		t.Fatal("dstnat in an output chain passed the portability check")
	}
	// And NFTApply refuses it as a FAILING component, loudly, without writing.
	path := filepath.Join(t.TempDir(), "rules.nft")
	actions, err := NFTApply(path, []byte(bad), func() bool { return true }, checkerFor(nil), "apply")
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("a non-portable ruleset was written to disk")
	}
	if len(actions) != 1 || actions[0].Kind == ActionNoChange {
		t.Fatalf("the refusal must be a failing action, not a NoChange: %+v", actions)
	}
	if aerr := actions[0].apply(context.Background()); aerr == nil || !strings.Contains(aerr.Error(), "dstnat") {
		t.Fatalf("applying the refusal must fail and name the cause, got %v", aerr)
	}
}
