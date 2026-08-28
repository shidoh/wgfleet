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
		"client_udp_divert": 1,
		"client_udp_tproxy": 1,
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
	if chainCountsEqual(live, want) {
		t.Error("a flushed chain compared equal; the drift probe cannot see the case it was written for")
	}

	// A rule added by hand is drift too.
	live["client_udp_tproxy"] = want["client_udp_tproxy"] + 1
	if chainCountsEqual(live, want) {
		t.Error("an added rule compared equal")
	}

	// And an untouched kernel must compare equal, or the reconciler thrashes.
	if !chainCountsEqual(want, want) {
		t.Error("an identical ruleset compared unequal")
	}

	// A missing chain entirely.
	delete(live, "egress_leak_guard")
	if chainCountsEqual(live, want) {
		t.Error("a missing chain compared equal")
	}
}

// chainCountsEqual mirrors TableMatches' comparison without needing a live kernel.
func chainCountsEqual(live, want map[string]int) bool {
	if len(live) != len(want) {
		return false
	}
	for c, n := range want {
		if live[c] != n {
			return false
		}
	}
	return true
}

// Unknown must never be reported as drift: a dev box with no nft would otherwise
// re-apply on every pass forever.
func TestTableMatchesReportsUnknownRatherThanDrift(t *testing.T) {
	if _, known := TableMatches("ip", "wgfleet_definitely_not_here", "chain x {\n\taccept\n}\n"); known {
		t.Skip("this box has nft and the table somehow exists")
	}
}
