package netfw

import (
	"strings"
	"testing"
)

func netnsInput() NetnsNATInput {
	return NetnsNATInput{PeerIface: "mih0", RedirAddr: "100.127.255.2:7895",
		TProxyAddr: "100.127.255.2:7896", ClientCIDR: "10.80.0.0/24",
		// Required: without it the rules that close mihomo's own listeners to clients
		// are the one thing that would silently not be rendered.
		SelfAddr: "100.127.255.2"}
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
		`iifname "mih0" ip saddr 10.80.0.0/24 ip saddr != 10.80.0.1 ip daddr != 100.127.255.2 meta l4proto udp counter drop`,
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
// drop for UDP — private networks, the management overlay and the exits'
// own public addresses, gone one way and silently.
func TestNetnsNATGuardsDirectDestinations(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface:   "mih0",
		RedirAddr:   "100.127.255.2:7895",
		TProxyAddr:  "100.127.255.2:7896",
		SelfAddr:    "100.127.255.2",
		ClientCIDR:  "10.80.0.0/24",
		DirectCIDRs: []string{"10.0.0.0/8", "172.29.0.0/16"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		// The namespace's own address joins the operator's list: mihomo answering on
		// it is a destination, not traffic to intercept.
		`iifname "mih0" ip saddr 10.80.0.0/24 ip saddr != 10.80.0.1 ip daddr != 10.0.0.0/8 ip daddr != 172.29.0.0/16 ip daddr != 100.127.255.2 ip protocol tcp dnat to`,
		`ip daddr != 172.29.0.0/16 ip daddr != 100.127.255.2 meta l4proto udp tproxy ip to`,
		`ip daddr != 172.29.0.0/16 ip daddr != 100.127.255.2 meta l4proto udp counter drop`,
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
		SelfAddr:   "100.127.255.2",
		ClientCIDR: "10.80.0.0/24",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "chain forward {") || !strings.Contains(out, `iifname "mih0" ip saddr 10.80.0.0/24 ip saddr != 10.80.0.1 counter`) {
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
		SelfAddr:    "100.127.255.2",
		ClientCIDR:  "10.80.0.0/24",
		DirectCIDRs: []string{"10.0.0.0/8; drop"},
	})
	if err == nil {
		t.Fatal("a crafted CIDR was rendered into the ruleset")
	}
}

// The interception must catch traffic that came FROM a client and nothing else.
//
// The veth carries both directions, so without a source scope the rules also match
// every answer mihomo is waiting for: WireGuard packets coming back from an exit,
// its own DNS replies, a geo-database download. Those are addressed to the
// namespace itself, no transparent socket matches them, and the fail-closed drop
// underneath eats them. Measured on a test stand: client UDP was
// intercepted and proxied correctly while mihomo could not resolve a single name,
// because its own answers died one hook before it reached them.
func TestNetnsNATOnlyInterceptsTrafficFromClients(t *testing.T) {
	out, err := RenderNetnsNAT(netnsInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `iifname "mih0"`) {
			continue
		}
		if !strings.Contains(line, "ip saddr 10.80.0.0/24") {
			t.Errorf("a rule matches everything arriving on the veth, mihomo's own replies included:\n  %s", line)
		}
	}
}

// A client pool is not optional: without it the rules cannot be scoped, and the
// unscoped version is a namespace that eats its own traffic.
func TestNetnsNATRefusesToRenderWithoutTheClientPool(t *testing.T) {
	in := netnsInput()
	in.ClientCIDR = ""
	if _, err := RenderNetnsNAT(in); err == nil {
		t.Fatal("an unscoped interception was rendered")
	}
}

// The gateway is the master's own address in the client pool, so it is where the
// fleet resolver answers from. Its replies land on this veth with a source inside
// the pool, and a scope written only as "from a client" hands them to a
// transparent socket that does not exist and drops them. Measured on a test
// stand: mihomo could not resolve a single name while the tunnel and the
// interception both worked.
func TestNetnsNATDoesNotInterceptRepliesFromTheGateway(t *testing.T) {
	out, err := RenderNetnsNAT(netnsInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "ip saddr 10.80.0.0/24") {
			continue
		}
		if !strings.Contains(line, "ip saddr != 10.80.0.1") {
			t.Errorf("a rule swallows the resolver's own replies:\n  %s", line)
		}
	}
}

// Traffic addressed to the namespace itself is FOR mihomo, never traffic to push
// THROUGH it.
//
// The sibling of the host's `ip daddr != <gateway>` guard, and it was missing. It
// matters the moment anything on the host redirects an admin connection in here:
// the host rewrites the destination to this address, the packet arrives with a
// destination no direct-CIDR guard covers, the interception claims it and sends it
// to the redirect port — and mihomo, asked to proxy a connection to itself, closes
// it. The symptom: the dashboard's TCP handshake completes and is immediately
// FIN'd, from the client tunnel only.
func TestNetnsNATDoesNotInterceptTrafficAddressedToMihomoItself(t *testing.T) {
	in := netnsInput()
	in.SelfAddr = "100.127.255.2"
	out, err := RenderNetnsNAT(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "dnat to") && !strings.Contains(line, "tproxy ip to") {
			continue
		}
		if !strings.Contains(line, "ip daddr != 100.127.255.2") {
			t.Errorf("a rule would intercept traffic aimed at mihomo itself:\n  %s", line)
		}
	}
}

// Client ping has to survive the move, and surviving it means changing address on
// the way out of this namespace.
//
// What made it die was invisible: the host's masquerade is scoped away from the
// veth, so the pass that carries a packet INTO the namespace takes the "no NAT"
// decision for the whole connection, and the pass that carries it back out cannot
// undo that. The source stays a client's, and the host's own leak guard drops it
// one hook later — nearly every packet in is a packet dropped.
func TestForwardedClientTrafficLeavesTheNamespaceWithTheNamespacesAddress(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface:  "mih0",
		ClientCIDR: "10.73.0.0/24",
		RedirAddr:  "100.127.255.2:7895",
		TProxyAddr: "100.127.255.2:7896",
		SelfAddr:   "100.127.255.2",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	post, ok := chainBody(out, "chain postrouting {")
	if !ok {
		t.Fatalf("the namespace masquerades nothing, so forwarded client traffic keeps a source the host will drop:\n%s", out)
	}
	for _, want := range []string{
		`oifname "mih0"`,        // on the way out, and only there
		"ip saddr 10.73.0.0/24", // a client's traffic
		"ip saddr != 10.73.0.1", // not the gateway's own
		"masquerade",
	} {
		if !strings.Contains(post, want) {
			t.Errorf("the namespace postrouting is missing %q:\n%s", want, post)
		}
	}
	if strings.Contains(post, "100.127.255.2 ") && !strings.Contains(post, "ip saddr 10.73.0.0/24") {
		t.Error("mihomo's own traffic must not be masqueraded here: it already leaves with this address")
	}
}

// The rule at pref 400 hands every client a route to this namespace, and the
// input chain's accept policy used to hand them everything mihomo binds on it.
// Measured from a client-position namespace on a test stand: the SOCKS bridge xray
// dials proxied for anyone, with no authentication, and the control API answered.
//
// A client has one legitimate destination here — the port its own intercepted TCP
// was redirected to. The host, which is what the bridge and the API are for, is
// not in the client pool and so is untouched by the rules that close this.
func TestAClientReachesOnlyTheRedirectOnTheNamespaceAddress(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface:  "mih0",
		ClientCIDR: "10.73.0.0/24",
		RedirAddr:  "100.127.255.2:7895",
		TProxyAddr: "100.127.255.2:7896",
		SelfAddr:   "100.127.255.2",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	in, ok := chainBody(out, "chain input {")
	if !ok {
		t.Fatalf("the namespace has no input chain:\n%s", out)
	}
	for _, want := range []string{
		"ip saddr 10.73.0.0/24 ip saddr != 10.73.0.1 ip daddr 100.127.255.2 tcp dport != 7895 counter drop",
		"ip saddr 10.73.0.0/24 ip saddr != 10.73.0.1 ip daddr 100.127.255.2 meta l4proto != tcp counter drop",
	} {
		if !strings.Contains(in, want) {
			t.Errorf("a client can still reach mihomo's own listeners; missing %q:\n%s", want, in)
		}
	}
	// And the host still can: nothing here names its address, which is the point.
	if strings.Contains(in, "100.127.255.1") {
		t.Errorf("the host end of the link is named in a client rule:\n%s", in)
	}
}

// The host forwards the Clash API port INTO the namespace for clients when the
// operator has put it in client_admin_ports. The namespace's own input closure
// must know the same list, or the host opens the door and the namespace slams it:
// client SYNs to the dashboard are dropped by the closure, conntrack full of UNREPLIED DNAT entries.
func TestAClientReachesTheAdminPortsTheHostForwardsIntoTheNamespace(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface:            "mih0",
		ClientCIDR:           "10.73.0.0/24",
		RedirAddr:            "100.127.255.2:7895",
		TProxyAddr:           "100.127.255.2:7896",
		SelfAddr:             "100.127.255.2",
		ClientForwardedPorts: []int{9090, 9090, 7895},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	in, ok := chainBody(out, "chain input {")
	if !ok {
		t.Fatalf("no input chain:\n%s", out)
	}
	want := "ip saddr 10.73.0.0/24 ip saddr != 10.73.0.1 ip daddr 100.127.255.2 tcp dport != { 7895, 9090 } counter drop"
	if !strings.Contains(in, want) {
		t.Errorf("the closure does not admit the forwarded admin port; want %q in:\n%s", want, in)
	}
}

// One source for "which admin port reaches the namespace from the client tunnel":
// the host's DNAT and the namespace's closure are rendered from the same answer.
func TestTheHostAndTheNamespaceAgreeOnTheClientAdminPort(t *testing.T) {
	api, admin := "172.29.3.10:9090", []int{9000, 9090, 51821}
	host, err := RenderMasterNAT(MasterNATInput{
		ClientInterface: "wg0", ClientCIDR: "10.73.0.0/24",
		RedirAddr: "10.73.0.1:7895", TProxyAddr: "10.73.0.1:7896",
		NetnsGateway: "100.127.255.2", NetnsHostIface: "mih-host",
		ClashAPI: api, ClientAdminPorts: admin,
	})
	if err != nil {
		t.Fatalf("host render: %v", err)
	}
	if !strings.Contains(host, `iifname "wg0" ip daddr 172.29.3.10 tcp dport 9090 dnat to 100.127.255.2:9090`) {
		t.Fatalf("the host no longer forwards the client admin port; the premise of this test is gone:\n%s", host)
	}
	ns, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface:            "mih0",
		ClientCIDR:           "10.73.0.0/24",
		RedirAddr:            "100.127.255.2:7895",
		TProxyAddr:           "100.127.255.2:7896",
		SelfAddr:             "100.127.255.2",
		ClientForwardedPorts: ClientForwardedPorts(api, admin),
	})
	if err != nil {
		t.Fatalf("namespace render: %v", err)
	}
	if !strings.Contains(ns, "tcp dport != { 7895, 9090 } counter drop") {
		t.Errorf("the namespace closure disagrees with the host about 9090:\n%s", ns)
	}
	// And when the operator has NOT opened it, neither side opens it.
	if got := ClientForwardedPorts(api, []int{9000}); len(got) != 0 {
		t.Errorf("9090 forwarded to clients without the opt-in: %v", got)
	}
	if got := ClientForwardedPorts("", admin); len(got) != 0 {
		t.Errorf("a port forwarded with no API address at all: %v", got)
	}
}

// The dashboard keeps its address for a client whose connection mihomo itself
// carries — a VLESS client, whose traffic xray hands to mihomo and mihomo dials
// from inside this namespace.
//
// That dial never touches the host's redirect: it leaves the namespace for the
// management address, where nothing has listened on the API port since the move,
// and is refused. Redirecting it on the host instead would send it straight back
// in wearing the namespace's own address as source. The symptom: the same URL
// answers 200 over AmneziaWG and an empty reply over VLESS, for as long as the client's fallback group sat on VLESS.
func TestClashAPIKeepsItsAddressForConnectionsMihomoDials(t *testing.T) {
	out, err := RenderNetnsNAT(NetnsNATInput{
		PeerIface: "mih0", ClientCIDR: "10.73.0.0/24",
		RedirAddr: "100.127.255.2:7895", TProxyAddr: "100.127.255.2:7896",
		SelfAddr:             "100.127.255.2",
		OperatorAPIAddr:      "172.29.3.10",
		ClientForwardedPorts: []int{9090},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// The priority is numeric on purpose: older nft refuses the named form in an
	// output chain, which leaves the node in Error.
	if !strings.Contains(out, "type nat hook output priority -100;") {
		t.Fatalf("no output NAT chain at priority -100 — a locally dialled connection is never redirected:\n%s", out)
	}
	want := "ip daddr 172.29.3.10 tcp dport 9090 dnat to 100.127.255.2:9090"
	if !strings.Contains(out, want) {
		t.Errorf("missing %q — the dashboard is refused for every client mihomo proxies:\n%s", want, out)
	}
}

// The redirect widens nothing: a port the operator has not opened to clients is
// not redirected, and with no operator address there is nothing to redirect from.
func TestClashAPIOutputRedirectFollowsTheClientAdminPorts(t *testing.T) {
	base := NetnsNATInput{
		PeerIface: "mih0", ClientCIDR: "10.73.0.0/24",
		RedirAddr: "100.127.255.2:7895", TProxyAddr: "100.127.255.2:7896",
		SelfAddr: "100.127.255.2",
	}
	closed := base
	closed.OperatorAPIAddr = "172.29.3.10"
	noAddr := base
	noAddr.ClientForwardedPorts = []int{9090}
	for name, in := range map[string]NetnsNATInput{"port not opened to clients": closed, "no operator address": noAddr} {
		out, err := RenderNetnsNAT(in)
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		if strings.Contains(out, "hook output") {
			t.Errorf("%s: an output redirect was rendered anyway:\n%s", name, out)
		}
	}
}
