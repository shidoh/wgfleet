package reconcile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNFTCheckUnavailable means the ruleset could not be CHECKED at all: there is
// no `nft` on this box (a dev laptop, a non-Linux build), or there is one that
// cannot answer — `nft -c` still opens a netlink socket to resolve a ruleset, so
// without CAP_NET_ADMIN it fails with "cache initialization failed: Operation not
// permitted" on EVERY input, valid or not. It is deliberately not the same as
// "the ruleset is bad": an unanswerable question must change nothing, the same
// rule the drift probe follows with its `known` bool. Refusing to write on a box
// that cannot check would break every dev run, every stand that has not installed
// nftables yet, and every unprivileged container — silently, since the refusal is
// a no-change entry and the pass stays green while the firewall never converges.
var ErrNFTCheckUnavailable = errors.New("nft check unavailable")

// checkRulesetWithNFT runs `nft -c -f` on the bytes. `-c` parses and resolves the
// ruleset and does NOT talk to the kernel, so it is safe to run during planning
// alongside the other read-only probes (`nft list table`, `ip rule list`).
//
// It is necessary but NOT sufficient: verified on the live fleet 2026-09-04
// (kernel 6.8.0-138, nft 1.0.9), `nft -c` accepts a `reject` statement in a
// prerouting chain that the nftables manual restricts to input/forward/output.
// Whatever only the kernel can reject is caught by the apply itself, which is
// atomic and therefore leaves the previous table in place.
func checkRulesetWithNFT(ruleset []byte) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return ErrNFTCheckUnavailable
	}
	f, err := os.CreateTemp("", "wgfleet-nftcheck-*.nft")
	if err != nil {
		return ErrNFTCheckUnavailable
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := f.Write(ruleset); err != nil {
		_ = f.Close()
		return ErrNFTCheckUnavailable
	}
	if err := f.Close(); err != nil {
		return ErrNFTCheckUnavailable
	}
	out, err := exec.Command("nft", "-c", "-f", name).CombinedOutput()
	if err == nil {
		return nil
	}
	// A verdict is only worth having from a checker that can also return the other
	// answer. Before believing a rejection, hand nft a ruleset it must accept
	// anywhere: if THAT is rejected too, what failed is the check, not the bytes.
	// Matching the failure by its message was the alternative and it is worse —
	// the wording is nft's to change, and getting it wrong turns every ruleset on
	// the node into a silent no-change.
	if !nftCanReturnBothAnswers() {
		return ErrNFTCheckUnavailable
	}
	// Do not leak the temp path into an operator-facing message.
	msg := strings.ReplaceAll(string(bytes.TrimSpace(out)), name, "<rendered ruleset>")
	if msg == "" {
		msg = err.Error()
	}
	return errors.New(msg)
}

// nftCanReturnBothAnswers reports whether `nft -c` accepts a ruleset that is
// valid by construction. It runs only after a rejection, so the extra process is
// paid on the rare path, never on a converged pass.
func nftCanReturnBothAnswers() bool {
	f, err := os.CreateTemp("", "wgfleet-nftprobe-*.nft")
	if err != nil {
		return false
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	// An empty table of a name nothing else uses: valid everywhere, and `-c` never
	// commits it, so nothing reaches the kernel even where the check does work.
	if _, err := f.WriteString("table inet wgfleet_nft_check_probe {\n}\n"); err != nil {
		_ = f.Close()
		return false
	}
	if err := f.Close(); err != nil {
		return false
	}
	return exec.Command("nft", "-c", "-f", name).Run() == nil
}

// NFTPreviousRuleset is where NFTApply keeps the last ruleset that was BOTH on
// disk and confirmed applied, at the moment a different one replaces it. It is
// the file the rollback runbook loads (`nft -f <path>.prev`) when a new ruleset
// turns out to be wrong in a way `nft -c` cannot see.
func NFTPreviousRuleset(rulesetPath string) string { return rulesetPath + ".prev" }

// NFTApply returns the actions that make the live kernel hold ruleset.
//
// The obvious shape — write the file, then run `nft -f` when the file changed —
// has a hole that closes over the node permanently. `nft -f` is atomic, so a
// FAILED apply leaves the PREVIOUS table in the kernel while the new bytes are
// already on disk. Next pass the file has not changed and a table is present, so
// the planner reports "ruleset already loaded" and stops. Disk says one thing, the
// kernel runs another, the node reports Ready, and nothing ever revisits it.
//
// The fix is to gate on what was APPLIED rather than on what was written. A marker
// beside the ruleset records the digest of the last apply that actually succeeded,
// written through OnApplied so a failed exec leaves it stale and the next pass
// retries. Presence in the kernel is still checked as well, because a reboot
// clears nft state without touching either file — and `loaded` is expected to ask
// the stronger question wherever it can: not "is a table by this name present" but
// "does it hold what we wrote". A present table with a chain someone flushed by hand
// is the case that leaked a client's DNS query in cleartext while four consecutive
// reconcile passes reported drift=0.
//
// The marker lives next to the ruleset rather than in /run on purpose: /run is
// cleared on reboot, and a reboot must re-apply because the KERNEL lost the table,
// not because the marker vanished. Those are different reasons and only the second
// one is observable from the marker.
// check validates the ruleset without touching the kernel; nil ⇒
// checkRulesetWithNFT. A parameter rather than a package variable, matching
// `loaded` beside it and every other injection point in this codebase: a mutable
// package var is invisible to `go vet`, and the first parallel test or concurrent
// caller would turn it into a silent data race.
func NFTApply(path string, ruleset []byte, loaded func() bool, check func([]byte) error, summary string) ([]Action, error) {
	return NFTApplyWith(nil, path, ruleset, loaded, check, summary)
}

// NFTApplyWith is NFTApply for a ruleset that has to be loaded somewhere other
// than this namespace: nftPrefix replaces the bare `nft` invocation (nil ⇒ `nft`),
// so a caller can pass `nsenter --net=<path> nft`.
//
// It exists because the second renderer this branch added went around all of the
// above — no pre-check, no applied marker, no previous ruleset, no kernel
// comparison — and did so in the ONE place where the consequences are least
// visible: a ruleset inside a namespace, where nobody runs `nft list ruleset` by
// reflex. That is an earlier finding in its purest form: a fix written for one resource is
// not a fix until it is applied to all of them.
func NFTApplyWith(nftPrefix []string, path string, ruleset []byte, loaded func() bool, check func([]byte) error, summary string) ([]Action, error) {
	if len(nftPrefix) == 0 {
		nftPrefix = []string{"nft"}
	}
	apply := func(extra string) Action {
		argv := append(append([]string(nil), nftPrefix...), "-f", path)
		return ExecAction(summary+extra, argv...)
	}
	if check == nil {
		check = checkRulesetWithNFT
	}
	// CHECK BEFORE WRITING. The old order — write, then `nft -f` — put bad bytes on
	// disk and returned an error that aborts the whole reconcile pass. On the master
	// masterNATPlanner sits near the end of the planner list, so its failure also
	// stops dockerfw, the resolver, the VLESS inbound and both mihomo self-heals,
	// every 30 seconds, indefinitely. And after a reboot the kernel has no table
	// while the same rejected file is still there to be replayed.
	//
	// A ruleset we cannot check is applied as before (see ErrNFTCheckUnavailable);
	// only one the checker actively REJECTS is refused, and refusing is a plan
	// entry rather than an error so the rest of the pass still runs.
	if err := check(ruleset); err != nil && !errors.Is(err, ErrNFTCheckUnavailable) {
		return []Action{NoChangeAction(filepath.Base(path),
			fmt.Sprintf("refusing to write a ruleset nft rejects: %v", err))}, nil
	}

	var actions []Action
	// Preserve the ruleset being REPLACED, but only if it was confirmed applied —
	// the file can also hold bytes that were written and then rejected by the
	// kernel, and keeping those as the way back is worse than keeping nothing.
	if prev, ok := lastGoodRuleset(path); ok && !bytes.Equal(prev, ruleset) {
		keep, err := FileAction(NFTPreviousRuleset(path), prev, 0o644, nil)
		if err != nil {
			return nil, err
		}
		actions = append(actions, keep)
	}

	file, err := FileAction(path, ruleset, 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions = append(actions, file)

	want := digestOf(ruleset)
	marker := path + ".applied"
	applied, _ := os.ReadFile(marker)
	record := func() { _ = os.WriteFile(marker, []byte(want), 0o644) }

	switch {
	case string(applied) != want:
		actions = append(actions, apply("").OnApplied(record))
	case !loaded():
		// The ruleset is the one we last applied, but the kernel no longer has the
		// table: a reboot cleared nft state, or someone flushed it by hand. Re-apply
		// to self-heal rather than run with no rules while reporting Ready.
		actions = append(actions, apply(" (kernel table missing)").OnApplied(record))
	default:
		actions = append(actions, NoChangeAction("nft -f", "ruleset applied and present in the kernel"))
	}
	return actions, nil
}

// NFTAppliedMarker is where NFTApply records a successful apply, exported so
// teardown can remove it alongside the ruleset it describes.
func NFTAppliedMarker(rulesetPath string) string { return rulesetPath + ".applied" }

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// lastGoodRuleset returns the on-disk ruleset when it is the one the applied
// marker vouches for. ok is false when the file is absent, unreadable, or holds
// bytes no successful apply ever confirmed.
func lastGoodRuleset(path string) ([]byte, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	applied, err := os.ReadFile(NFTAppliedMarker(path))
	if err != nil {
		return nil, false
	}
	if string(applied) != digestOf(content) {
		return nil, false
	}
	return content, true
}
