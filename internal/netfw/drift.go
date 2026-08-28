package netfw

import (
	"encoding/json"
	"os/exec"
	"strings"
)

// Kernel drift detection for a rendered nft table.
//
// TableLoaded answers "is a table with this name present", and for a long time that
// was the whole self-heal: the reconciler re-applied when the table had vanished
// (a reboot) and otherwise reported no change. It could not see the case that
// actually happens to a live node — the table is present and its CONTENTS are not
// what we wrote. Measured on a rehearsal: `nft flush chain ip wgfleet_master
// client_udp_tproxy`, and one second later a client's DNS query left the master's
// uplink in cleartext while four consecutive reconcile passes logged
// `changes=0 drift=0`. The sibling policy-routing half of the same planner checks
// kernel CONTENT and repaired itself in five seconds.
//
// The comparison is per-chain rule COUNTS rather than rule semantics. Byte equality
// is not available — the kernel normalises everything it prints — and a full
// semantic diff would be a second implementation of nftables. Counts catch what
// goes wrong in practice: a flushed chain drops to zero, a deleted rule drops by
// one, a hand-added rule rises by one. What they miss is an in-place `nft replace`
// of one rule by another of equal length, which is a deliberate act by someone who
// has already decided to fight the reconciler.

// TableMatches reports whether the live kernel table holds the same chains and the
// same number of rules per chain as ruleset describes.
//
// known is false when the question could not be answered at all — nft missing, a
// non-Linux box, unparseable output. Callers must treat unknown as "leave it
// alone": re-applying on every pass because we cannot see the kernel would turn a
// dev box into a restart loop.
func TableMatches(family, name, ruleset string) (matches, known bool) {
	live, err := kernelChainCounts(family, name)
	if err != nil {
		return false, false
	}
	want := renderedChainCounts(ruleset)
	if len(want) == 0 {
		return false, false
	}
	if len(live) != len(want) {
		return false, true
	}
	for chain, n := range want {
		if live[chain] != n {
			return false, true
		}
	}
	return true, true
}

// nftJSON is the shape `nft -j list table` emits: a flat list of tagged objects.
type nftJSON struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftNamed struct {
	Name  string `json:"name"`
	Chain string `json:"chain"`
}

func kernelChainCounts(family, name string) (map[string]int, error) {
	out, err := exec.Command("nft", "-j", "list", "table", family, name).Output()
	if err != nil {
		return nil, err
	}
	var doc nftJSON
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, obj := range doc.Nftables {
		if raw, ok := obj["chain"]; ok {
			var c nftNamed
			if err := json.Unmarshal(raw, &c); err == nil && c.Name != "" {
				if _, seen := counts[c.Name]; !seen {
					counts[c.Name] = 0
				}
			}
		}
		if raw, ok := obj["rule"]; ok {
			var r nftNamed
			if err := json.Unmarshal(raw, &r); err == nil && r.Chain != "" {
				counts[r.Chain]++
			}
		}
	}
	return counts, nil
}

// renderedChainCounts walks the ruleset we wrote and counts the rules we asked for
// in each chain. The chain's own `type ... hook ...; policy ...;` declaration is
// part of the chain, not a rule, and neither are comments or blank lines — the
// kernel counts none of them either.
func renderedChainCounts(ruleset string) map[string]int {
	counts := map[string]int{}
	chain := ""
	for _, raw := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{"):
			chain = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{"))
			counts[chain] = 0
		case line == "}":
			chain = ""
		case chain == "":
			continue
		case strings.HasPrefix(line, "type ") && strings.Contains(line, "hook "):
			continue
		default:
			counts[chain]++
		}
	}
	return counts
}
