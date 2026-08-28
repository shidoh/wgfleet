package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

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
func NFTApply(path string, ruleset []byte, loaded func() bool, summary string) ([]Action, error) {
	file, err := FileAction(path, ruleset, 0o644, nil)
	if err != nil {
		return nil, err
	}
	actions := []Action{file}

	want := digestOf(ruleset)
	marker := path + ".applied"
	applied, _ := os.ReadFile(marker)
	record := func() { _ = os.WriteFile(marker, []byte(want), 0o644) }

	switch {
	case string(applied) != want:
		actions = append(actions, ExecAction(summary, "nft", "-f", path).OnApplied(record))
	case !loaded():
		// The ruleset is the one we last applied, but the kernel no longer has the
		// table: a reboot cleared nft state, or someone flushed it by hand. Re-apply
		// to self-heal rather than run with no rules while reporting Ready.
		actions = append(actions, ExecAction(summary+" (kernel table missing)", "nft", "-f", path).OnApplied(record))
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
