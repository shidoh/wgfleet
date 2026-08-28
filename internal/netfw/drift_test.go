package netfw

import (
	"reflect"
	"testing"
)

// The renderer's own output is the reference the kernel is compared against, so
// counting it wrong is the same as not checking at all.
func TestRenderedChainCountsIgnoresEverythingTheKernelIgnores(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		TProxyAddr:      "10.80.0.1:7896",
		PrivateCIDRs:    []string{"192.168.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := renderedChainCounts(out)
	want := map[string]int{
		"prerouting":        1, // the tcp dnat; the QUIC drop is gone once UDP is proxied
		"client_udp_tproxy": 2, // intercept, then drop what was not intercepted
		"postrouting":       1,
		"egress_leak_guard": 1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chain counts = %v, want %v", got, want)
	}
	// The shebang, the "do not edit" comment, the table/delete-table preamble and
	// every `type ... hook ...; policy ...;` line must contribute nothing: the kernel
	// counts none of them as rules either.
	for _, chain := range []string{"", "table ip wgfleet_master"} {
		if _, present := got[chain]; present {
			t.Errorf("preamble leaked into the chain map as %q", chain)
		}
	}
}

// A flushed chain is the case this exists for: the table is present, so the old
// presence-only probe saw nothing wrong, while client UDP left the master in the
// clear and four passes in a row reported drift=0.
func TestTableMatchesSeesAFlushedChain(t *testing.T) {
	ruleset, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.80.0.0/24",
		RedirAddr: "10.80.0.1:7895", TProxyAddr: "10.80.0.1:7896",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := renderedChainCounts(ruleset)

	// Same chains, but one of them emptied by hand.
	live := map[string]int{}
	for k, v := range want {
		live[k] = v
	}
	live["client_udp_tproxy"] = 0
	if chainCountsMatch(live, want) {
		t.Error("a flushed chain compared equal; the drift probe cannot see the case it was written for")
	}

	// A rule added by hand is drift too.
	live["client_udp_tproxy"] = want["client_udp_tproxy"] + 1
	if chainCountsMatch(live, want) {
		t.Error("an added rule compared equal")
	}

	// And an untouched kernel must compare equal, or the reconciler thrashes.
	if !chainCountsMatch(want, want) {
		t.Error("an identical ruleset compared unequal")
	}

	// A missing chain entirely.
	delete(live, "egress_leak_guard")
	if chainCountsMatch(live, want) {
		t.Error("a missing chain compared equal")
	}
}

// Unknown must never be reported as drift: a dev box with no nft would otherwise
// re-apply on every pass forever. And unknown must be reported as unknown — the
// first version of this test skipped on `known` and fell off the end otherwise, so
// it could not fail either way.
func TestTableMatchesReportsUnknownRatherThanDrift(t *testing.T) {
	matches, known := TableMatches("ip", "wgfleet_definitely_not_here", "chain x {\n\taccept\n}\n")
	if known {
		t.Fatalf("a table that does not exist was reported as a known answer (matches=%v)", matches)
	}
	if matches {
		t.Error("an unanswerable probe claimed the kernel matches")
	}
	// An empty ruleset is not a claim that the kernel is empty: nothing was rendered,
	// so there is nothing to compare against and the honest answer is "unknown".
	if _, known := TableMatches("ip", "wgfleet_definitely_not_here", ""); known {
		t.Error("an empty ruleset was treated as an answerable comparison")
	}
}

// A set or map declared beside the chains must not be attributed to a chain, and its
// closing brace must not end the chain before it. Getting this wrong is not a silent
// inaccuracy: a count that can never match the kernel makes every pass see drift, so
// `nft -f` runs every 30 seconds forever on a healthy node.
func TestRenderedChainCountsWalksPastNestedBlocks(t *testing.T) {
	ruleset := `table ip wgfleet_master {
	set direct_v4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8,
		             192.168.0.0/16 }
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr != 10.80.0.1 tcp dport 1-65535 dnat to 10.80.0.1:7895
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.80.0.0/24 masquerade
	}
}
`
	got := renderedChainCounts(ruleset)
	want := map[string]int{"prerouting": 1, "postrouting": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chain counts = %v, want %v", got, want)
	}
}
