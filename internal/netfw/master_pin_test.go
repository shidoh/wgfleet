package netfw

import (
	"strings"
	"testing"
)

func pinnedNATInput(pins ...PinnedExit) MasterNATInput {
	return MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		NetnsHostIface:  "mih-host",
		NetnsLinkCIDR:   "100.127.255.0/30",
		PinnedExits:     pins,
	}
}

var exitPin = PinnedExit{Exit: "198.51.100.7:35555", Master: "203.0.113.1:41234"}

func TestMasterNATWithoutPinsRendersNoneOfTheGate(t *testing.T) {
	out, err := RenderMasterNAT(pinnedNATInput())
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{AWGHeardSet, "awg_exit_", "snat to"} {
		if strings.Contains(out, absent) {
			t.Errorf("no pinned exits, yet the ruleset mentions %q:\n%s", absent, out)
		}
	}
}

func TestMasterNATPinsTheExitInitiatedFlow(t *testing.T) {
	out, err := RenderMasterNAT(pinnedNATInput(exitPin))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		// The exit's knock refreshes the set — in a filter chain, because a nat
		// chain sees only the first packet of a flow and keepalives would never
		// extend it.
		"set " + AWGHeardSet + " {",
		"flags dynamic,timeout",
		"type filter hook prerouting priority mangle",
		"ip saddr 198.51.100.7 udp sport 35555 udp dport 41234 update @" + AWGHeardSet + " { ip saddr }",
		// The knock itself is refused before the master's whitelist can accept it:
		// an accepted knock is a confirmed conntrack entry occupying the tuple the
		// SNAT below needs.
		"type filter hook input priority filter - 10",
		"ip saddr 198.51.100.7 udp sport 35555 udp dport 41234 ct state new drop",
		// The gate: only a NEW flow waits for the exit, so a re-render that empties
		// the set never cuts a tunnel already carrying traffic.
		"type filter hook forward priority filter - 10",
		"type filter hook output priority filter - 10",
		"ip daddr 198.51.100.7 udp dport 35555 ct state new ip daddr != @" + AWGHeardSet + " counter drop",
		// And the pin, to an explicit address: masquerade would take the
		// interface's primary address, not the one the exit knocks on.
		"ip daddr 198.51.100.7 udp dport 35555 snat to 203.0.113.1:41234",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("pinned ruleset missing %q:\n%s", want, out)
		}
	}
}

// NAT is decided by the first rule that matches; the pin must come before the
// masquerade that would otherwise take mihomo's namespace traffic.
func TestMasterNATPinPrecedesTheMasquerade(t *testing.T) {
	out, err := RenderMasterNAT(pinnedNATInput(exitPin))
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Index(out, "snat to 203.0.113.1:41234")
	masq := strings.Index(out, `ip saddr 100.127.255.0/30 oifname != "mih-host" masquerade`)
	if pin < 0 || masq < 0 || pin > masq {
		t.Fatalf("pin at %d must precede the namespace masquerade at %d:\n%s", pin, masq, out)
	}
}

func TestMasterNATRejectsMalformedPins(t *testing.T) {
	for name, pin := range map[string]PinnedExit{
		"exit without port":     {Exit: "198.51.100.7", Master: "203.0.113.1:41234"},
		"master without port":   {Exit: "198.51.100.7:35555", Master: "203.0.113.1"},
		"ipv6 exit":             {Exit: "[2001:db8::7]:35555", Master: "203.0.113.1:41234"},
		"nft syntax in address": {Exit: "198.51.100.7:35555; flush ruleset", Master: "203.0.113.1:41234"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderMasterNAT(pinnedNATInput(pin)); err == nil {
				t.Fatalf("pin %+v accepted", pin)
			}
		})
	}
}

// The drift probe counts rules per chain. A miscount here is `nft -f` every pass,
// and every pass would empty the heard set — so the set block and the rule that
// ends in `{ ip saddr }` must each be read exactly as the kernel counts them.
func TestPinnedRulesetCountsAsTheKernelWould(t *testing.T) {
	out, err := RenderMasterNAT(pinnedNATInput(exitPin))
	if err != nil {
		t.Fatal(err)
	}
	counts := renderedChainCounts(out)
	for chain, want := range map[string]int{
		"awg_exit_knock": 1, "awg_exit_knock_input": 1, "awg_exit_gate_forward": 1, "awg_exit_gate_output": 1,
	} {
		if counts[chain] != want {
			t.Errorf("chain %s counted %d rules, want %d (all counts: %v)", chain, counts[chain], want, counts)
		}
	}
	if _, isChain := counts[AWGHeardSet]; isChain {
		t.Errorf("the set %s was counted as a chain: %v", AWGHeardSet, counts)
	}
}
