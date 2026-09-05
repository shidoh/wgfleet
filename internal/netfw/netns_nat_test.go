package netfw

import (
	"strings"
	"testing"
)

func netnsInput() NetnsNATInput {
	return NetnsNATInput{PeerIface: "mih0", RedirAddr: "100.127.255.2:7895", TProxyAddr: "100.127.255.2:7896"}
}

// The interception must arrive in the namespace intact: TCP redirected, UDP
// intercepted, and anything the interception missed dropped rather than
// forwarded.
func TestNetnsNATInterceptsBothProtocols(t *testing.T) {
	out, err := RenderNetnsNAT(netnsInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"dnat to 100.127.255.2:7895",
		"tproxy ip to 100.127.255.2:7896",
		`iifname "mih0" meta l4proto udp counter drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// `tproxy` must come BEFORE `meta mark set`. nft_tproxy_eval returns NFT_BREAK
// when no transparent socket is listening, which ends the rule — so a mark
// written first rides on a packet that was never intercepted and sends it
// somewhere it does not belong. This is the same trap the host ruleset carries a
// paragraph about, and moving the rules must not lose it.
func TestNetnsNATMarksOnlyAfterASuccessfulInterception(t *testing.T) {
	out, err := RenderNetnsNAT(netnsInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "tproxy ip to") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no tproxy rule:\n%s", out)
	}
	if i, j := strings.Index(line, "tproxy ip to"), strings.Index(line, "meta mark set"); i > j {
		t.Errorf("the mark is set before the tproxy, so a failed interception still marks the packet:\n\t%s", line)
	}
}

// The table must be replaced, not appended to: `nft -f` stacks rules otherwise,
// and this renders on every reconcile pass.
func TestNetnsNATReplacesItsTable(t *testing.T) {
	out, err := RenderNetnsNAT(netnsInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "delete table ip "+NetnsNATTable) {
		t.Errorf("the ruleset appends instead of replacing:\n%s", out)
	}
}

// Missing inputs must be refused rather than rendered into a ruleset that
// intercepts into nothing — which fails closed and takes client UDP with it.
func TestNetnsNATRefusesIncompleteInput(t *testing.T) {
	for name, in := range map[string]NetnsNATInput{
		"no interface": {RedirAddr: "a:1", TProxyAddr: "a:2"},
		"no redir":     {PeerIface: "mih0", TProxyAddr: "a:2"},
		"no tproxy":    {PeerIface: "mih0", RedirAddr: "a:1"},
	} {
		if _, err := RenderNetnsNAT(in); err == nil {
			t.Errorf("%s: rendered anyway", name)
		}
	}
}

// Once the interception moves, the HOST must stop intercepting — both halves, TCP
// and UDP. Leaving either behind sends client traffic to listeners that are no
// longer in this namespace: TCP to a refused connection, UDP into the fail-closed
// drop. That is every client's traffic, gone, in the same pass that was supposed
// to fix them.
func TestMasterNATStopsInterceptingOnceTheNamespaceHasIt(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.73.0.0/24",
		RedirAddr: "10.73.0.1:7895", TProxyAddr: "10.73.0.1:7896",
		NetnsGateway: "100.127.255.2", NetnsHostIface: "mih-host",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "tproxy ip to") {
		t.Errorf("the host still intercepts UDP after the move:\n%s", out)
	}
	if strings.Contains(out, "dnat to 10.73.0.1:7895") {
		t.Errorf("the host still redirects TCP after the move:\n%s", out)
	}
}

// The veth must be exempt from BOTH the masquerade and the leak guard, and the
// two are one requirement rather than two.
//
// Masquerading on the way in would present every client as the host end of the
// veth, and mihomo — which works precisely because TPROXY does not rewrite the
// packet — could not answer the right one. Exempting the masquerade alone then
// leaves the source in the client pool, so the leak guard one hook later matches
// and drops it: a partial fix turns a broken reply path into no path at all.
func TestMasterNATExemptsTheNamespaceVethFromBothGuards(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.73.0.0/24",
		RedirAddr: "10.73.0.1:7895", TProxyAddr: "10.73.0.1:7896",
		NetnsGateway: "100.127.255.2", NetnsHostIface: "mih-host",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, chain := range []string{"chain postrouting {", "chain egress_leak_guard {"} {
		body, ok := chainBody(out, chain)
		if !ok {
			t.Fatalf("chain %q not rendered:\n%s", chain, out)
		}
		if !strings.Contains(body, `oifname != "mih-host"`) {
			t.Errorf("chain %q does not exempt the namespace veth:\n%s", chain, body)
		}
	}
}

// Without the move, the ruleset must be exactly what it was: this is the state
// every node is in until it migrates, and most nodes will be in it for a while.
func TestMasterNATIsUnchangedWithoutTheMove(t *testing.T) {
	out, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.73.0.0/24",
		RedirAddr: "10.73.0.1:7895", TProxyAddr: "10.73.0.1:7896",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "tproxy ip to 10.73.0.1:7896") {
		t.Errorf("the host stopped intercepting without being asked to:\n%s", out)
	}
	if strings.Contains(out, "mih-host") {
		t.Errorf("a namespace exemption leaked into a node that has not moved:\n%s", out)
	}
}

// Destination exemptions are the second line of defence. The first is a routing
// rule that keeps them out of the namespace; if one reaches here anyway, an
// unguarded ruleset meets it with an unconditional DNAT for TCP and a fail-closed
// drop for UDP — the corporate networks, the management overlay and the exits'
// own public addresses, gone one way and silently.
func TestNetnsNATGuardsDirectDestinations(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface:   "mih0",
		RedirAddr:   "100.127.255.2:7895",
		TProxyAddr:  "100.127.255.2:7896",
		DirectCIDRs: []string{"10.0.0.0/8", "172.29.0.0/16"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		`iifname "mih0" ip daddr != 10.0.0.0/8 ip daddr != 172.29.0.0/16 ip protocol tcp dnat to`,
		`ip daddr != 172.29.0.0/16 meta l4proto udp tproxy ip to`,
		`ip daddr != 172.29.0.0/16 meta l4proto udp counter drop`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// Everything that is not TCP or UDP — client ICMP above all — is not intercepted
// in here; it reaches the forward hook and goes on to the host. The counter is
// what makes that sentence checkable: before it, "client ICMP still works" was an
// assumption with nothing behind it, and the client-path prober cannot settle it
// either because its gateway ping is answered locally.
func TestNetnsNATCountsWhatItForwards(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface: "mih0", RedirAddr: "100.127.255.2:7895", TProxyAddr: "100.127.255.2:7896",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "chain forward {") || !strings.Contains(out, `iifname "mih0" counter`) {
		t.Errorf("nothing accounts for the protocols this namespace merely forwards:\n%s", out)
	}
	if !strings.Contains(out, "ct state invalid drop") {
		t.Errorf("the namespace does not drop invalid-state packets (2026-07-27):\n%s", out)
	}
}

// A crafted direct CIDR must not reach a root-applied ruleset verbatim.
func TestNetnsNATRefusesACraftedDirectCIDR(t *testing.T) {
	_, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface: "mih0", RedirAddr: "100.127.255.2:7895", TProxyAddr: "100.127.255.2:7896",
		DirectCIDRs: []string{"10.0.0.0/8; drop"},
	})
	if err == nil {
		t.Fatal("a crafted CIDR was rendered into the ruleset")
	}
}
