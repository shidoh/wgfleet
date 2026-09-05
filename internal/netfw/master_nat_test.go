package netfw

import (
	"fmt"
	"strings"
	"testing"
)

func TestRenderMasterNAT(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table ip wgfleet_master",
		// Atomic replace (delete-first) so re-applies don't accumulate duplicate
		// DNAT/masquerade rules or leave stale ones from an older binary.
		"delete table ip wgfleet_master",
		`iifname "wg0" ip daddr != 10.0.0.0/8 ip daddr != 172.16.0.0/12 ip daddr != 192.168.0.0/16 udp dport 443 drop`,
		`ip protocol tcp dnat to 10.80.0.1:7895`,
		// Masquerade on every egress except back into the client interface, so the
		// overlay/DNS path is NAT'd too (not only the public uplink).
		`ip saddr 10.80.0.0/24 oifname != "wg0" masquerade`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master NAT missing %q:\n%s", want, out)
		}
	}
}

func TestRenderMasterNATEgressLeakGuard(t *testing.T) {
	// The master masquerades its client pool just as an exit does, so it inherits the
	// same failure: a packet conntrack cannot place carries no NAT binding and would
	// leave with a client's private source, after which upstream returns replies to
	// that address and conntrack rewrites the source port to resolve the collision.
	// The guard asserts the outcome — nothing leaves with a pool source — and must run
	// AFTER srcnat so translated packets have already stopped matching.
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"chain egress_leak_guard",
		"type filter hook postrouting priority srcnat + 10",
		// Two exclusions the exit's copy of this rule has carried for a while and
		// this one did not. Without `oifname != "lo"` the master cannot reach its own
		// portal or resolver, which both bind the gateway address: the packet leaves
		// over loopback WITH the gateway as its source and the guard eats it (measured
		// on a rehearsal — the counter moved by seven while curl timed out). Without
		// `ip saddr != <gateway>` the master's own originated traffic is judged by a
		// rule written for traffic it forwards on a client's behalf.
		`ip saddr 10.80.0.0/24 ip saddr != 10.80.0.1 oifname != "wg0" oifname != "lo" counter drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master egress leak guard missing %q:\n%s", want, out)
		}
	}

	// The guard must use the CANONICAL pool, never the raw operator string — this
	// ruleset is applied as root, so an unparsed CIDR here would be an injection point
	// exactly as it is for the masquerade.
	out2, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.7/24",
		RedirAddr:       "10.80.0.1:7895",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out2, `ip saddr 10.80.0.0/24 ip saddr != 10.80.0.1 oifname != "wg0" oifname != "lo" counter drop`) {
		t.Errorf("guard did not canonicalize the client pool:\n%s", out2)
	}
}

func TestRenderMasterNATRejectsCIDRInjection(t *testing.T) {
	// A crafted direct-CIDR value must never reach the rendered nft script verbatim:
	// it is parsed and re-emitted canonically, so injection attempts fail the render.
	if _, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"10.0.0.0/8 ; flush ruleset"},
	}); err == nil {
		t.Fatal("expected error for nft-injecting private CIDR")
	}
	// A bad client CIDR is likewise rejected.
	if _, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "not-a-cidr",
		RedirAddr:       "10.80.0.1:7895",
	}); err == nil {
		t.Fatal("expected error for malformed client CIDR")
	}
}

func TestRenderMasterNATCanonicalizesCIDRs(t *testing.T) {
	// A host-bit-dirty CIDR is masked to its canonical network form in the output.
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.7/24", // host bits set
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"10.1.2.3/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ip saddr 10.80.0.0/24") {
		t.Errorf("client CIDR not canonicalized to 10.80.0.0/24:\n%s", out)
	}
	if !strings.Contains(out, "ip daddr != 10.0.0.0/8") {
		t.Errorf("private CIDR not canonicalized to 10.0.0.0/8:\n%s", out)
	}
}

func TestRenderMasterNATRequiresFields(t *testing.T) {
	if _, err := RenderMasterNAT(MasterNATInput{ClientInterface: "wg0"}); err == nil {
		t.Fatal("expected error for missing CIDR/redir")
	}
	// Egress interface is no longer required — masquerade covers all non-client
	// egress — so the core three fields are sufficient.
	if _, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.80.0.0/24", RedirAddr: "10.80.0.1:7895",
	}); err != nil {
		t.Fatalf("unexpected error with the required fields present: %v", err)
	}
}

// Traffic a client addresses to the GATEWAY ITSELF must never be proxied: it is
// not internet-bound traffic, it is a request to a service the master runs for
// its clients — the self-service portal, a local resolver. Found on a live
// rehearsal, where the portal bound on 10.80.0.1 was silently swallowed by this
// redirect and simply never answered.
func TestMasterNATLeavesTrafficToTheGatewayAlone(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		PrivateCIDRs:    []string{"192.168.0.0/16"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "dnat to") {
			continue
		}
		if !strings.Contains(line, "ip daddr != 10.80.0.1") {
			t.Fatalf("the redirect swallows traffic addressed to the gateway itself:\n%s", line)
		}
	}
}

// Client UDP must reach mihomo, not the master's own uplink.
//
// The only DNAT the master ever rendered was `ip protocol tcp`, and QUIC on 443
// was dropped so browsers fell back to TCP. Everything else a client sent over UDP
// — DNS to a resolver that is not the gateway, QUIC on any other port, WebRTC,
// games, DoQ — traversed a forward chain with policy accept, got masqueraded, and
// left the MASTER's public uplink. The user saw "connected through an exit"; the
// observer on that uplink saw their UDP sourced at the master, never at an exit.
// TPROXY is the standard answer: intercept in mangle/prerouting and hand the
// packet to a transparent socket without rewriting it.
func TestMasterNATSendsClientUDPToMihomo(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		TProxyAddr:      "10.80.0.1:7896",
		PrivateCIDRs:    []string{"192.168.0.0/16"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	// The interception itself, on new flows.
	if !strings.Contains(out, "tproxy ip to 10.80.0.1:7896") {
		t.Errorf("no tproxy rule; client UDP still leaves the master's own uplink:\n%s", out)
	}
	// No divert chain: `socket transparent 1` is a TCP idiom that for UDP can only
	// ever match datagrams addressed to mihomo's own listeners — which the guard
	// below deliberately excludes — and accepting those bypasses the input drop
	// policy into the self-dial shape of an earlier finding.
	if strings.Contains(out, "socket transparent 1") {
		t.Errorf("the divert chain is back; it accepts client UDP addressed to mihomo itself:\n%s", out)
	}
	// The same exemptions the TCP redirect honours: private destinations stay
	// DIRECT, and traffic to the gateway is a request to the master's own services
	// (the portal, the resolver), never internet traffic to route through an exit.
	tproxyLine := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "tproxy ip to") {
			tproxyLine = line
		}
	}
	for _, want := range []string{`iifname "wg0"`, "ip daddr != 192.168.0.0/16", "ip daddr != 10.80.0.1"} {
		if !strings.Contains(tproxyLine, want) {
			t.Errorf("tproxy rule is missing %q:\n\t%s", want, tproxyLine)
		}
	}
	// A datagram the tproxy could not take must be DROPPED, not forwarded. Measured
	// on the stand: with mihomo stopped, the client's DNS kept working and left the
	// MASTER's own uplink — the exact leak this chain exists to end, invisible to the
	// user because nothing broke.
	dropLine := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "meta l4proto udp counter drop") {
			dropLine = line
		}
	}
	if dropLine == "" {
		t.Errorf("no drop for un-intercepted client UDP; a stopped proxy leaks out the master's uplink:\n%s", out)
	}
	for _, want := range []string{`iifname "wg0"`, "ip daddr != 192.168.0.0/16", "ip daddr != 10.80.0.1"} {
		if !strings.Contains(dropLine, want) {
			t.Errorf("the drop is not scoped like the rule above it, missing %q:\n\t%s", want, dropLine)
		}
	}

	// Statement order decides what a FAILED interception does. nft_tproxy_eval
	// returns NFT_BREAK when no transparent socket is listening, ending the rule —
	// so a mark written before the tproxy stays on a packet that was never
	// intercepted, and the policy route then delivers it to the master's own local
	// sockets past a drop policy. Written after, the same failure just forwards.
	if i, j := strings.Index(tproxyLine, "tproxy ip to"), strings.Index(tproxyLine, "meta mark set"); i > j {
		t.Errorf("the mark is set before the tproxy, so a failed interception still marks the packet:\n\t%s", tproxyLine)
	}
}

// With no tproxy target configured the ruleset must render exactly as before —
// an agent that cannot intercept UDP still has to serve TCP.
func TestMasterNATWithoutTProxyIsUnchanged(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "tproxy") {
		t.Errorf("rendered a tproxy rule with no target:\n%s", out)
	}
	if !strings.Contains(out, "dnat to 10.80.0.1:7895") {
		t.Errorf("the TCP redirect must survive:\n%s", out)
	}
}

// With TPROXY in place the QUIC drop must go, or it shadows the interception it
// was a stand-in for.
//
// The drop lives at the `dstnat` hook (priority -100) and the interception at
// `mangle` (-150), so despite reading first in the rendered file it runs SECOND.
// Measured on a rehearsal: client UDP to :5353 and :4433 reached an exit while :443
// produced no mihomo entry and nothing on the tunnel — every client's HTTP/3
// black-holed until it timed out into TCP, which is itself a shape worth avoiding,
// while mihomo's sniffer was configured for QUIC on exactly that port.
func TestMasterNATStopsDroppingQUICOnceItCanProxyIt(t *testing.T) {
	with, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.80.0.0/24",
		RedirAddr: "10.80.0.1:7895", TProxyAddr: "10.80.0.1:7896",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(with, "udp dport 443 drop") {
		t.Errorf("QUIC is still dropped while UDP is intercepted; the drop shadows the tproxy:\n%s", with)
	}

	// Without an interception target the drop is still the right answer: the only
	// alternative is letting QUIC leave the master's own uplink.
	without, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.80.0.0/24", RedirAddr: "10.80.0.1:7895",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(without, "udp dport 443 drop") {
		t.Errorf("with no UDP path, QUIC must still be dropped rather than leaked:\n%s", without)
	}
}

// The refusal set and the ruleset are two statements about the same rule, and the
// check that reads the first one is only as good as their agreement. This asserts
// it by reading the rendered text back: a port claimed refused must appear in a
// drop rule, and a drop rule on a port must be claimed.
//
// Written this way rather than as two hardcoded expectations because the failure
// it guards against is drift — someone deletes the drop and leaves the claim, and
// the UDP-return check goes on vouching for a port nothing refuses any more.
func TestRefusedUDPPortsMatchesTheRenderedDrops(t *testing.T) {
	base := MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
	}
	for _, tc := range []struct {
		name string
		in   MasterNATInput
	}{
		{"no tproxy listener: QUIC is dropped", base},
		{"tproxy listener: QUIC is proxied", func() MasterNATInput {
			in := base
			in.TProxyAddr = "10.80.0.1:7896"
			return in
		}()},
		{"interception moved into the namespace", func() MasterNATInput {
			in := base
			in.TProxyAddr = "10.80.0.1:7896"
			in.NetnsGateway = "100.127.255.2"
			in.NetnsHostIface = "mih-host"
			in.NetnsLinkCIDR = "100.127.255.0/30"
			return in
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ruleset, err := RenderMasterNAT(tc.in)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			claimed := map[int]bool{}
			for _, p := range RefusedUDPPorts(tc.in) {
				claimed[p] = true
			}
			rendered := map[int]bool{}
			for _, line := range strings.Split(ruleset, "\n") {
				var port int
				if !strings.Contains(line, "udp dport") || !strings.HasSuffix(strings.TrimSpace(line), "drop") {
					continue
				}
				if _, err := fmt.Sscanf(strings.TrimSpace(line[strings.Index(line, "udp dport"):]), "udp dport %d", &port); err == nil {
					rendered[port] = true
				}
			}
			for p := range claimed {
				if !rendered[p] {
					t.Errorf("port %d is claimed refused but no rule drops it: the UDP-return check would vouch for a black hole", p)
				}
			}
			for p := range rendered {
				if !claimed[p] {
					t.Errorf("port %d is dropped by a rule but not claimed refused: the check would report a black hole nobody can act on", p)
				}
			}
		})
	}
}

// The port the client interface itself listens on is NOT refused. This is the
// blocker the review found: while `accepted` meant "a port this node holds", 443
// was accounted for by virtue of being the black hole and the alert could never
// fire on it.
func TestRefusedUDPPortsDoesNotAccountForTheClientWGPort(t *testing.T) {
	in := MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		TProxyAddr:      "10.80.0.1:7896",
	}
	if got := RefusedUDPPorts(in); len(got) != 0 {
		t.Fatalf("a master with a live TPROXY listener refuses nothing, yet it claims %v", got)
	}
}

// A full move keeps nothing on the host: leaving the interception in place would
// feed listeners that are no longer here — TCP to a refused connection, UDP into
// the fail-closed drop, which is every client's traffic gone.
func TestFullMoveStopsTheHostIntercepting(t *testing.T) {
	in := MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		TProxyAddr:      "10.80.0.1:7896",
		NetnsGateway:    "100.127.255.2",
		NetnsHostIface:  "mih-host",
	}
	out, err := RenderMasterNAT(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, unwanted := range []string{"dnat to", "tproxy ip to"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the host still intercepts (%q) after the interception moved:\n%s", unwanted, out)
		}
	}
}

// Everything mihomo sends once it lives in the namespace — exit endpoints, WARP,
// the management overlay, geo databases — leaves with the namespace's address as
// its source. Nothing on the way out rewrote it: the only masquerade matched the
// CLIENT pool, and this link is not in it. Not one master↔exit tunnel would have
// come up.
func TestNamespaceLinkIsMasqueraded(t *testing.T) {
	in := MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		TProxyAddr:      "10.80.0.1:7896",
		NetnsGateway:    "100.127.255.2",
		NetnsHostIface:  "mih-host",
		NetnsLinkCIDR:   "100.127.255.0/30",
	}
	out, err := RenderMasterNAT(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, `ip saddr 100.127.255.0/30 oifname != "mih-host" masquerade`) {
		t.Errorf("mihomo's own traffic leaves with an unroutable source:\n%s", out)
	}
}

// The masquerade and the leak guard must both exempt the veth, so a gateway with
// no interface name is refused rather than rendered into a ruleset that eats the
// traffic it was changed to let past.
func TestNamespaceGatewayWithoutTheVethIsRefused(t *testing.T) {
	_, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0",
		ClientCIDR:      "10.80.0.0/24",
		RedirAddr:       "10.80.0.1:7895",
		NetnsGateway:    "100.127.255.2",
	})
	if err == nil {
		t.Fatal("a namespace gateway with no veth name was rendered")
	}
}
