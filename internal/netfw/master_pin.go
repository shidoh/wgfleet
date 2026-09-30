package netfw

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// AWGHeardSet names the dynamic set of exits the master has heard knocking on
// their pinned port (exit-initiated AWG flow). The gate lets a NEW flow to an
// exit through only while the exit is in it.
const AWGHeardSet = "awg_exit_heard"

// AWGHeardTimeout is how long one knock keeps an exit in AWGHeardSet. It must
// stay SHORTER than the time the path filter remembers a flow: an exit gone quiet
// longer than the filter remembers is an exit whose next packet on the tuple is
// the MASTER's, and the filter then records the master as the initiator. Twice
// the widest keepalive (wg.KeepaliveFor draws 15–28 s) keeps one lost keepalive
// from closing the gate.
const AWGHeardTimeout = 60 * time.Second

// PinnedExit is one master↔exit AWG tunnel whose flow the exit starts: the exit's
// endpoint and the master's pinned external address, both "ip:port".
type PinnedExit struct {
	Exit   string
	Master string
}

type pinnedTuple struct {
	exitIP     netip.Addr
	exitPort   uint16
	masterIP   netip.Addr
	masterPort uint16
}

// parsePins canonicalises every pin from its parsed form, so nothing in the
// input can reach this root-applied ruleset as raw text.
func parsePins(pins []PinnedExit) ([]pinnedTuple, error) {
	out := make([]pinnedTuple, 0, len(pins))
	for _, p := range pins {
		exit, err := netip.ParseAddrPort(p.Exit)
		if err != nil || !exit.Addr().Is4() {
			return nil, fmt.Errorf("netfw master NAT: pinned exit %q is not an IPv4 ip:port", p.Exit)
		}
		master, err := netip.ParseAddrPort(p.Master)
		if err != nil || !master.Addr().Is4() {
			return nil, fmt.Errorf("netfw master NAT: pinned master address %q is not an IPv4 ip:port", p.Master)
		}
		out = append(out, pinnedTuple{exit.Addr(), exit.Port(), master.Addr(), master.Port()})
	}
	return out, nil
}

// renderPinGate writes the set and the three filter chains of the exit-initiated
// flow into the master's NAT table. Everything lives in that table on purpose:
// an older agent rebuilds the table without them, so a rollback leaves nothing
// behind.
func renderPinGate(b *strings.Builder, pins []pinnedTuple) {
	if len(pins) == 0 {
		return
	}
	fmt.Fprintf(b, "\tset %s {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout %ds\n\t}\n\n",
		AWGHeardSet, int(AWGHeardTimeout.Seconds()))

	// Every packet of the exit's flow refreshes the set. A filter chain, because a
	// nat chain sees only a flow's first packet and keepalives would never extend it.
	b.WriteString("\tchain awg_exit_knock {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	for _, p := range pins {
		fmt.Fprintf(b, "\t\tip saddr %s udp sport %d udp dport %d update @%s { ip saddr }\n",
			p.exitIP, p.exitPort, p.masterPort, AWGHeardSet)
	}
	b.WriteString("\t}\n\n")

	// The knock is never accepted, even from a whitelisted address: an accepted
	// knock confirms a conntrack entry whose reply tuple is the one the SNAT below
	// needs, and mihomo's flow would then collide with it for as long as the exit
	// keeps knocking. A drop here is final, whatever the filter table says later.
	b.WriteString("\tchain awg_exit_knock_input {\n")
	b.WriteString("\t\ttype filter hook input priority filter - 10; policy accept;\n")
	for _, p := range pins {
		fmt.Fprintf(b, "\t\tip saddr %s udp sport %d udp dport %d ct state new drop\n",
			p.exitIP, p.exitPort, p.masterPort)
	}
	b.WriteString("\t}\n\n")

	// The gate. Only a NEW flow waits for the exit: the set empties on every
	// re-render of this table, and gating established traffic would cut a working
	// tunnel until the next keepalive. forward covers mihomo in its namespace,
	// output covers mihomo on the host.
	for _, hook := range []string{"forward", "output"} {
		fmt.Fprintf(b, "\tchain awg_exit_gate_%s {\n", hook)
		fmt.Fprintf(b, "\t\ttype filter hook %s priority filter - 10; policy accept;\n", hook)
		for _, p := range pins {
			fmt.Fprintf(b, "\t\tip daddr %s udp dport %d ct state new ip daddr != @%s counter drop\n",
				p.exitIP, p.exitPort, AWGHeardSet)
		}
		b.WriteString("\t}\n\n")
	}
}

// renderPinSNAT writes the pins at the head of the postrouting chain, ahead of
// every masquerade: NAT is decided by the first rule that matches.
func renderPinSNAT(b *strings.Builder, pins []pinnedTuple) {
	for _, p := range pins {
		fmt.Fprintf(b, "\t\tip daddr %s udp dport %d snat to %s:%d\n",
			p.exitIP, p.exitPort, p.masterIP, p.masterPort)
	}
}
