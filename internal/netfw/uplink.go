package netfw

import (
	"fmt"
	"strings"
)

// Named counters for the master's own TCP handshakes on its uplink address.
// internal/metrics reads every counter named uplink_* as
// wgfleet_fw_uplink_handshake_packets_total{direction}.
const (
	UplinkSynOutCounter   = "uplink_syn_out"
	UplinkSynAckInCounter = "uplink_synack_in"
)

// renderUplinkCounters counts the SYNs the master sends from in.UplinkAddr and
// the SYN-ACKs that come back to it. Their ratio is the master's handshake
// health: a filter that drops or delays SYNs past the kernel's 1 s retransmit
// makes the host send more SYNs per answer: a filtered path shows noticeably
// more SYNs than SYN-ACKs, a clean one about one to one.
//
// Counting only, never a verdict: both chains accept everything. The SYN is
// counted after source NAT (a SYN from mihomo's namespace carries the host's
// address only then) and the SYN-ACK before destination NAT (while it still
// does). Keyed on the address, not an interface, so the client tunnel and the
// namespace veth — whose handshakes carry other addresses — stay out of it.
func renderUplinkCounters(b *strings.Builder, in RenderInput) {
	if !in.UplinkAddr.Is4() {
		return
	}
	ip := in.UplinkAddr.String()
	fmt.Fprintf(b, "\n\tcounter %s {\n\t}\n", UplinkSynOutCounter)
	fmt.Fprintf(b, "\tcounter %s {\n\t}\n", UplinkSynAckInCounter)
	b.WriteString("\n\tchain uplink_syn_out {\n")
	b.WriteString("\t\ttype filter hook postrouting priority srcnat + 50; policy accept;\n")
	fmt.Fprintf(b, "\t\tip saddr %s tcp flags & (syn | ack) == syn counter name %q\n", ip, UplinkSynOutCounter)
	b.WriteString("\t}\n")
	b.WriteString("\n\tchain uplink_synack_in {\n")
	b.WriteString("\t\ttype filter hook prerouting priority dstnat - 50; policy accept;\n")
	fmt.Fprintf(b, "\t\tip daddr %s tcp flags & (syn | ack) == (syn | ack) counter name %q\n", ip, UplinkSynAckInCounter)
	b.WriteString("\t}\n")
}
