package master

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

func netnsSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role:     domain.RoleMaster,
		WGServer: domain.WGServerSpec{AddressPool: "10.73.0.0/24"},
		Master:   &domain.MasterSpec{BindAddress: "10.73.0.1", ClientViaNetns: "auto"},
	}
}

// With the knob on, the link is built — and only the link. Nothing about where
// client traffic goes changes here; that is a separate decision taken later in
// the pass, which is what makes this safe to converge on a live master.
func TestNetnsPlannerBuildsTheLinkWhenAsked(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, "docker inspect") {
			return "777\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	acts, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run}.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	changing := 0
	for _, a := range acts {
		dump += a.Summary + "\n"
		if a.Changes() {
			changing++
		}
	}
	if changing == 0 {
		t.Fatalf("nothing would be built:\n%s", dump)
	}
	if !strings.Contains(dump, "veth") {
		t.Errorf("the veth is never created:\n%s", dump)
	}
}

// A disabled master with nothing installed changes nothing.
//
// It does READ the kernel, and that is the point of the read: "off" is a state to
// converge to, so the planner has to look before it can say there is nothing to
// undo. What it must not do is act when the answer is "nothing".
func TestNetnsPlannerRespectsOff(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "off"
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case line == "ip rule list":
			return "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n", nil
		case strings.Contains(line, "route show table 51822"):
			return "", nil
		}
		return "", errors.New("absent")
	}
	acts, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run, clientIface: "wg0"}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("a disabled master with nothing installed would change %q", a.Summary)
		}
	}
}

// A holder that is not up yet must DEFER, not fail. This planner runs ahead of
// the master NAT and mihomo, and the engine stops at the first planner error — so
// failing over a container that the compose planner created one step earlier
// would stop the node converging anything at all.
func TestNetnsPlannerDefersWhenTheHolderIsNotUpYet(t *testing.T) {
	run := func(context.Context, string, ...string) (string, error) {
		return "", errors.New("No such object: wgfleet-netns")
	}
	acts, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run}.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("a missing holder failed the pass: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Summary + " | " + a.Display + "\n"
		if a.Changes() {
			t.Errorf("a deferred pass would change %q", a.Summary)
		}
	}
	if !strings.Contains(dump, "pending") {
		t.Errorf("the deferral does not say it is waiting:\n%s", dump)
	}
}

// The routing rule must name the REAL client interface.
//
// An earlier version derived it from an empty path and produced ".", a name no
// interface has: the rule installed cleanly and matched nothing, while the host
// ruleset had already been told to stop intercepting. That is every client's
// traffic unintercepted — the exact outage this change exists to prevent, caused
// by the change itself. Nothing caught it because no test set attached=true.
func TestAttachedNamespaceRoutesTheRealClientInterface(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, "docker inspect") {
			return "4242\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{
		run:         run,
		attached:    func() bool { return true },
		clientIface: "wg0",
		nftPath:     t.TempDir() + "/netns.nft",
	}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	if !strings.Contains(dump, "ip rule add iif wg0 lookup 51822 pref 400") {
		t.Errorf("the routing rule does not name the client interface:\n%s", dump)
	}
	if strings.Contains(dump, `iif .`) || strings.Contains(dump, "iif  ") {
		t.Errorf("the routing rule names an interface that cannot exist:\n%s", dump)
	}
	for _, want := range []string{"nft -f", "ip route replace default via 100.127.255.2"} {
		if !strings.Contains(dump, want) {
			t.Errorf("missing %q:\n%s", want, dump)
		}
	}
}

// Without a name there must be NO rule. Installing one with an empty iif applies
// cleanly and matches nothing, and by then the host has stopped intercepting.
func TestAttachedNamespaceRefusesWithoutAClientInterface(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if strings.Contains(name+" "+strings.Join(args, " "), "docker inspect") {
			return "4242\n", nil
		}
		return "", errors.New("absent")
	}
	p := netnsPlanner{run: run, attached: func() bool { return true }, nftPath: t.TempDir() + "/n.nft"}
	if _, err := p.Plan(context.Background(), netnsSpec()); err == nil {
		t.Fatal("rendered a routing rule with no client interface to match")
	}
}

// An unset knob builds the link, exactly as "auto" does: the fix ships on, and an
// operator who wants the old path sets "off".
func TestNetnsPlannerBuildsTheLinkWhenTheKnobIsUnset(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientViaNetns = ""
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, "docker inspect") {
			return "777\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	acts, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	changing := 0
	for _, a := range acts {
		if a.Changes() {
			changing++
		}
	}
	if changing == 0 {
		t.Error("an unconfigured master built nothing; the migration ships on by default")
	}
}

// A knob nobody can read is a refusal, not a guess. The planner reports it so the
// operator learns about the typo from the plan rather than from the traffic.
func TestNetnsPlannerRefusesAKnobItCannotRead(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "of"
	_, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: func(context.Context, string, ...string) (string, error) {
		return "", nil
	}}.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("a mistyped knob converged silently")
	}
	if !strings.Contains(err.Error(), "client_via_netns") {
		t.Errorf("the error does not name the knob: %v", err)
	}
}

// A per-client selection is refused, and the refusal explains itself.
//
// It was implemented, documented, and measured on the stand 2026-09-05 doing the
// opposite of what its name promised: mihomo moves as a whole, so the host went on
// steering every client OUTSIDE the prefix at listeners that had left — the blast
// radius of a "canary" was everyone except the canary. `tproxy` can only reach a
// socket in its own namespace and there is one mihomo, so this is not deferred
// work.
func TestPerClientSelectionIsRefused(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "10.73.0.7/32"
	_, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: func(context.Context, string, ...string) (string, error) {
		return "", nil
	}}.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("a per-client selection was accepted; it breaks every client outside the prefix")
	}
	if !strings.Contains(err.Error(), "cannot be taken per client") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// attachedPlan runs the planner with the interception attached and returns every
// action's display line, which is what an operator reads in `--plan`.
func attachedPlan(t *testing.T, spec domain.NodeSpec, out map[string]string) string {
	t.Helper()
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if v, ok := out[line]; ok {
			return v, nil
		}
		if strings.Contains(line, "docker inspect") {
			return "4242\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{
		run:         run,
		attached:    func() bool { return true },
		clientIface: "wg0",
		nftPath:     t.TempDir() + "/netns.nft",
		nftCheck:    func([]byte) error { return nil },
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	return dump
}

// TPROXY only assigns the socket; the routing decision happens after prerouting.
// Without a policy route for the mark the kernel looks at a destination that
// still belongs to somebody else and sends the packet out the default route, so
// the transparent socket never sees a datagram. The host has carried this pair
// since TPROXY was introduced there; the namespace got the nft rule and not the
// routing.
func TestNamespaceCarriesTheTProxyPolicyRoute(t *testing.T) {
	dump := attachedPlan(t, netnsSpec(), nil)
	for _, want := range []string{
		"ip rule add fwmark 0x2 lookup 51821",
		"ip route replace local 0.0.0.0/0 dev lo table 51821",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("missing %q — tproxy assigns a socket nothing delivers to:\n%s", want, dump)
		}
	}
	// And it must happen INSIDE the namespace, not on the host, where the pair
	// already exists and means something else.
	for _, line := range strings.Split(dump, "\n") {
		if strings.Contains(line, "51821") && !strings.Contains(line, "nsenter") {
			t.Errorf("the namespace's tproxy routing was installed on the host: %q", line)
		}
	}
}

// The routing rule takes the whole client interface, and table 51822 holds one
// default route into the namespace — so every destination that must stay off the
// proxy goes with it unless something keeps it out first. That is the corporate
// networks, the management overlay, the exits' own public addresses
// and client-to-client traffic. The failure is the same shape as the outage this
// change exists to end: partial, one-way, invisible to every component metric.
func TestDirectDestinationsAreKeptOutOfTheNamespace(t *testing.T) {
	spec := netnsSpec()
	spec.Master.DirectCIDRs = []string{"10.0.0.0/8", "172.29.0.0/16", "203.0.113.7/32"}
	dump := attachedPlan(t, spec, nil)
	for _, cidr := range append(spec.Master.DirectCIDRs, spec.WGServer.AddressPool) {
		want := "ip rule add to " + cidr + " lookup main pref 390"
		if !strings.Contains(dump, want) {
			t.Errorf("missing %q — that destination would be swallowed by the namespace:\n%s", want, dump)
		}
	}
	// Lower priority than the rule that moves traffic, or it is never consulted.
	if netnsDirectRulePref >= 400 {
		t.Fatalf("the exemption priority %d does not sort ahead of the move", netnsDirectRulePref)
	}
}

// A CIDR the operator removed must stop being exempt. Left behind, that
// destination silently keeps bypassing the proxy forever.
func TestWithdrawnDirectDestinationsAreRemoved(t *testing.T) {
	dump := attachedPlan(t, netnsSpec(), map[string]string{
		"ip rule list": "0:\tfrom all lookup local\n" +
			"390:\tfrom all to 198.51.100.0/24 lookup main\n" +
			"32766:\tfrom all lookup main\n",
	})
	if !strings.Contains(dump, "ip rule del to 198.51.100.0/24 lookup main pref 390") {
		t.Errorf("a withdrawn exemption was left in the kernel:\n%s", dump)
	}
}

// The in-namespace ruleset must go through the same machinery as every other one:
// a pre-check before the bytes are written, an applied marker so a FAILED apply is
// not recorded as done, the previous ruleset kept as a way back. It went around
// all of it, in the one place where a missing table is least visible.
func TestInNamespaceRulesetGoesThroughNFTApply(t *testing.T) {
	dump := attachedPlan(t, netnsSpec(), nil)
	if !strings.Contains(dump, "nsenter --net=/proc/4242/ns/net nft -f") {
		t.Errorf("the ruleset is not applied inside the namespace:\n%s", dump)
	}
}

// A ruleset nft rejects must not be written, here as anywhere else.
func TestInNamespaceRulesetIsRefusedWhenNFTRejectsIt(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if strings.Contains(name+" "+strings.Join(args, " "), "docker inspect") {
			return "4242\n", nil
		}
		return "", errors.New("absent")
	}
	nftPath := t.TempDir() + "/netns.nft"
	p := netnsPlanner{
		run: run, attached: func() bool { return true }, clientIface: "wg0", nftPath: nftPath,
		nftCheck: func([]byte) error { return errors.New("syntax error, unexpected junk") },
	}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	if strings.Contains(dump, "nft -f") {
		t.Errorf("a rejected ruleset was still going to be applied:\n%s", dump)
	}
	if _, err := os.Stat(nftPath); err == nil {
		t.Error("a rejected ruleset was written to disk anyway")
	}
}

// Converged means silent. These used to be bare execs: every pass deleted the rule
// and added it back, and between the two calls a client packet takes the main
// table, leaves by the master's uplink and is masqueraded — the precise leak the
// fail-closed drop exists to prevent, opened twice a minute by the code that
// installs it.
func TestConvergedRoutingIsNotReinstalledEveryPass(t *testing.T) {
	dump := attachedPlan(t, netnsSpec(), map[string]string{
		"ip rule list":              "400:\tfrom all iif wg0 lookup 51822\n",
		"ip route show table 51822": "default via 100.127.255.2 dev mih-host\n",
	})
	if strings.Contains(dump, "ip rule del pref 400") {
		t.Errorf("a converged rule was torn down and rebuilt:\n%s", dump)
	}
	if strings.Contains(dump, "ip rule add iif wg0") {
		t.Errorf("a rule already in the kernel was added again:\n%s", dump)
	}
}

// The way back. `ip rule pref 400` sorts ahead of the TPROXY mark rule at 32765,
// so a rule left behind after mihomo has moved back sends every marked client
// packet into a namespace that is empty or gone — and it also swallows every
// destination the exemptions were protecting. The branch simply stopped ADDING
// actions when the decision flipped, which left the automatic revert leaving
// clients worse off than the move did.
func TestDetachRemovesEverythingTheMoveInstalled(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case line == "ip rule list":
			return "390:\tfrom all to 10.0.0.0/8 lookup main\n400:\tfrom all iif wg0 lookup 51822\n", nil
		case strings.Contains(line, "route show table 51822"):
			return "default via 100.127.255.2 dev mih-host\n", nil
		case strings.Contains(line, "nft list table ip wgfleet_netns"):
			return "table ip wgfleet_netns {}\n", nil
		}
		return "", errors.New("absent")
	}
	p := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run, attached: func() bool { return false }, clientIface: "wg0"}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	for _, want := range []string{
		"ip rule del pref 400",
		"ip rule del to 10.0.0.0/8 lookup main pref 390",
		"ip route flush table 51822",
		"nft delete table ip wgfleet_netns",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("the way back does not %q:\n%s", want, dump)
		}
	}
}

// The in-namespace interception is fail-closed: once mihomo has moved back out,
// `tproxy` finds no transparent socket and the next rule drops the datagram. So a
// ruleset left behind turns the namespace into a black hole for its OWN UDP —
// including the DNS query the readiness gate makes before the next attempt, which
// is a node that can never move again because its last revert broke the check
// that would have let it. Measured on the stand 2026-09-05: 38 dropped datagrams.
func TestDetachRemovesTheInNamespaceRuleset(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case strings.Contains(line, "nft list table ip wgfleet_netns"):
			return "table ip wgfleet_netns {}\n", nil
		case line == "ip rule list":
			return "0:\tfrom all lookup local\n", nil
		}
		return "", errors.New("absent")
	}
	p := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run, attached: func() bool { return false }, clientIface: "wg0"}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	if !strings.Contains(dump, "nsenter --net=/proc/4242/ns/net nft delete table ip wgfleet_netns") {
		t.Fatalf("the namespace keeps dropping its own UDP after the revert:\n%s", dump)
	}
}

// A detached master with nothing left over must be silent, or every pass reports
// changes forever.
func TestDetachIsSilentWhenNothingWasInstalled(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case line == "ip rule list":
			return "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n", nil
		case strings.Contains(line, "route show table 51822"):
			return "", nil
		}
		return "", errors.New("absent")
	}
	p := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run, attached: func() bool { return false }, clientIface: "wg0"}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range acts {
		if strings.Contains(a.Display, "ip rule del") || strings.Contains(a.Display, "route flush") {
			t.Errorf("a clean host was cleaned again: %q", a.Display)
		}
	}
}

// `network_mode: container:X` is resolved when the container is created, so a
// holder that restarts comes back with a NEW namespace while mihomo stays in the
// old one — alive, healthy by every container check, and reachable by nothing.
// `depends_on` orders startup, not restarts, and nothing was watching.
func TestMihomoIsPutBackWhenTheHolderRestartedWithoutIt(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect -f {{.State.Pid}} wgfleet-netns"):
			return "4242\n", nil
		case strings.Contains(line, "docker inspect -f {{.State.Pid}} mihomo"):
			return "5150\n", nil
		case line == "readlink /proc/5150/ns/net":
			return "net:[4026532000]\n", nil // the namespace the holder used to own
		case line == "readlink /proc/4242/ns/net":
			return "net:[4026532999]\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{
		run: run, attached: func() bool { return true }, clientIface: "wg0",
		nftPath: t.TempDir() + "/netns.nft", nftCheck: func([]byte) error { return nil },
		composePath: "/etc/wgfleet/docker-compose.yml",
	}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	if !strings.Contains(dump, "--force-recreate mihomo") {
		t.Errorf("mihomo was left in a namespace nothing routes into:\n%s", dump)
	}
}

// And when the two agree, nothing is recreated: bouncing mihomo costs every client
// connection it holds.
func TestMihomoIsLeftAloneWhenItIsInTheRightNamespace(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect -f {{.State.Pid}} wgfleet-netns"):
			return "4242\n", nil
		case strings.Contains(line, "docker inspect -f {{.State.Pid}} mihomo"):
			return "5150\n", nil
		case line == "readlink /proc/5150/ns/net", line == "readlink /proc/4242/ns/net":
			return "net:[4026532999]\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{
		run: run, attached: func() bool { return true }, clientIface: "wg0",
		nftPath: t.TempDir() + "/netns.nft", nftCheck: func([]byte) error { return nil },
		composePath: "/etc/wgfleet/docker-compose.yml",
	}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range acts {
		if strings.Contains(a.Display, "force-recreate") {
			t.Errorf("a correctly placed mihomo was bounced anyway: %q", a.Display)
		}
	}
}

// The documented way out of the migration is "set client_via_netns: off and let
// the agent converge". That has to actually converge.
//
// The disabled branch used to return before any cleanup, so the operator's own
// back-out left the routing rule at priority 400 in place — ahead of the TPROXY
// mark rule — sending every client packet into a namespace that mihomo had just
// left. The automatic revert had been cleaning up properly all along, which is
// why nothing caught this: the path a user takes was the one path not exercised.
func TestDisablingTheKnobCleansUpWhatTheMoveInstalled(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case strings.Contains(line, "nft list table ip wgfleet_netns"):
			return "table ip wgfleet_netns {}\n", nil
		case line == "ip rule list":
			return "390:\tfrom all to 10.0.0.0/8 lookup main\n400:\tfrom all iif wg0 lookup 51822\n", nil
		case strings.Contains(line, "route show table 51822"):
			return "default via 100.127.255.2 dev mih-host\n", nil
		}
		return "", errors.New("absent")
	}
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "off"

	acts, err := netnsPlanner{nftPath: t.TempDir() + "/netns.nft", run: run, clientIface: "wg0"}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	for _, want := range []string{
		"ip rule del pref 400",
		"ip rule del to 10.0.0.0/8 lookup main pref 390",
		"ip route flush table 51822",
		"nft delete table ip wgfleet_netns",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("turning the knob off does not %q:\n%s", want, dump)
		}
	}
}

// The kernel prints a single host as `to 192.168.105.4`, with no prefix length,
// while the spec carries `192.168.105.4/32`. Compared as strings they never match,
// so the rule is added on every pass, `ip rule add` returns EEXIST, and — because
// the action was not best-effort — the engine stopped the whole pass there.
//
// A master whose direct CIDRs contain any host address fails to converge ANYTHING
// after this planner, every thirty seconds, for ever. The controller derives
// exactly such addresses: the master's own public IP and one per exit. Reproduced
// on the stand 2026-09-05 as state=Error on every pass.
func TestHostAddressExemptionsAreNotReAddedEveryPass(t *testing.T) {
	spec := netnsSpec()
	spec.Master.DirectCIDRs = []string{"10.0.0.0/8", "192.168.105.4/32"}
	dump := attachedPlan(t, spec, map[string]string{
		"ip rule list": "390:\tfrom all to 10.0.0.0/8 lookup main\n" +
			"390:\tfrom all to 192.168.105.4 lookup main\n" +
			"400:\tfrom all iif wg0 lookup 51822\n",
		"ip route show table 51822": "default via 100.127.255.2 dev mih-host\n",
	})
	if strings.Contains(dump, "ip rule add to 192.168.105.4/32") {
		t.Errorf("an exemption already in the kernel was added again; the pass dies on EEXIST:\n%s", dump)
	}
	if strings.Contains(dump, "ip rule del to 192.168.105.4") {
		t.Errorf("a live exemption was read as withdrawn and removed:\n%s", dump)
	}
}

// And when one of them genuinely cannot be installed, it must not take the rest of
// the pass down with it: mihomo, the master NAT, DOCKER-USER and the resolver all
// converge after this planner, and the engine stops at the first fatal failure.
func TestExemptionFailuresDoNotAbortThePass(t *testing.T) {
	spec := netnsSpec()
	spec.Master.DirectCIDRs = []string{"10.0.0.0/8"}
	dumpActions := func() []reconcile.Action {
		run := func(_ context.Context, name string, args ...string) (string, error) {
			line := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(line, "docker inspect"):
				return "4242\n", nil
			case line == "ip rule list":
				return "0:\tfrom all lookup local\n", nil
			}
			return "", errors.New("absent")
		}
		p := netnsPlanner{
			run: run, attached: func() bool { return true }, clientIface: "wg0",
			nftPath: t.TempDir() + "/netns.nft", nftCheck: func([]byte) error { return nil },
		}
		acts, err := p.Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		return acts
	}
	var found bool
	for _, a := range dumpActions() {
		if !strings.Contains(a.Display, "ip rule add to 10.0.0.0/8") {
			continue
		}
		found = true
		if !a.NonFatal {
			t.Errorf("an exemption that fails would freeze everything after this planner: %q", a.Display)
		}
	}
	if !found {
		t.Error("the exemption was never planned at all")
	}
}

// The veth is pinned to the UPLINK's MTU, not left alone and not derived from a
// client tunnel.
//
// "Leave it at the default" is right on a fresh node and wrong on every node that
// already ran a build which narrowed it: removing the code that sets a value does
// not unset the value. Measured on the stand — the veth kept 1360 across the
// upgrade, because nothing recreates a link that already exists.
func TestVethMTUIsPinnedToTheUplinkNotTheClientTunnel(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientWG = &domain.ClientWGSpec{MTU: 1360}
	dump := attachedPlan(t, spec, nil)
	if strings.Contains(dump, "mtu 1360") {
		t.Errorf("the veth was sized to the client tunnel; mihomo's own tunnel packets do not fit:\n%s", dump)
	}
}

// The rule that sends clients into the namespace must never exist before the table
// it points at is usable.
//
// `ip rule ... lookup` is not terminal: a lookup that finds nothing falls through
// to the next rule and ends in `main`, whose default is the uplink. So a rule
// installed ahead of its route does not fail — it quietly routes every client out
// of the master's public address until the route lands. The two used to be
// rendered in exactly that order.
//
// The blackhole is the same argument for the window we cannot order our way out
// of: the namespace holder is `restart: unless-stopped`, and when it is recreated
// the veth dies, the kernel withdraws the route that used it, and the rule remains.
// Until the next pass the table is empty again. A floor makes that state drop
// packets instead of leaking them.
func TestTheNamespaceTableIsFilledAndFlooredBeforeTheRulePointsAtIt(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, "docker inspect") {
			return "4242\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{
		run: run, attached: func() bool { return true }, clientIface: "wg0",
		nftPath: t.TempDir() + "/netns.nft",
	}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	floor, route, rule := -1, -1, -1
	for i, a := range acts {
		switch {
		case strings.Contains(a.Display, "route replace blackhole default"):
			floor = i
		case strings.Contains(a.Display, "ip route replace default via 100.127.255.2"):
			route = i
		case strings.Contains(a.Display, "ip rule add iif wg0 lookup 51822"):
			rule = i
		}
	}
	if floor < 0 {
		t.Fatalf("the namespace table has no floor, so a miss falls through to the uplink:\n%s", displays(acts))
	}
	if route < 0 || rule < 0 {
		t.Fatalf("the plan does not both route and rule:\n%s", displays(acts))
	}
	if !(floor < route && route < rule) {
		t.Errorf("order must be floor → route → rule, got floor=%d route=%d rule=%d:\n%s",
			floor, route, rule, displays(acts))
	}
	if !strings.Contains(acts[floor].Display, "table 51822") {
		t.Errorf("the floor is not in the namespace table:\n%s", acts[floor].Display)
	}
}

// A node that converged under an older build already has the rule and the route,
// and only the floor is missing. Installing it must not cost that node a delete
// and re-add of a working rule — the gap between those two calls is the leak this
// whole block exists to avoid, and it would be opened by the code that closes it.
func TestAMissingFloorDoesNotTearDownAWorkingRule(t *testing.T) {
	// A world where the veth, the rule and the route are all already right, and the
	// floor is the only thing an older build did not install.
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect -f {{.State.Pid}}"):
			return "4242\n", nil
		case strings.Contains(line, "readlink"):
			return "net:[4026532999]\n", nil
		case strings.Contains(line, "-br link show mih-host"):
			return "mih-host UP 100.127.255.1/30\n", nil
		case strings.Contains(line, "-br link show mih0"):
			return "mih0 UP 100.127.255.2/30\n", nil
		case strings.Contains(line, "-br addr show mih-host"):
			return "mih-host UP 100.127.255.1/30\n", nil
		case strings.Contains(line, "-br addr show mih0"):
			return "mih0 UP 100.127.255.2/30\n", nil
		case strings.Contains(line, "link show mih-host"), strings.Contains(line, "link show mih0"):
			return "1: x: <BROADCAST> mtu 1500 qdisc noqueue\n", nil
		case strings.Contains(line, "ip_forward"), strings.Contains(line, "rp_filter"):
			return "1\n", nil
		case line == "ip rule list":
			return "400:\tfrom all iif wg0 lookup 51822\n", nil
		case strings.Contains(line, "route show table 51822"):
			return "default via 100.127.255.2 dev mih-host\n", nil // no floor
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{
		run: run, attached: func() bool { return true }, clientIface: "wg0",
		nftPath: t.TempDir() + "/netns.nft", nftCheck: func([]byte) error { return nil },
	}
	acts, err := p.Plan(context.Background(), netnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	dump := displays(acts)
	if !strings.Contains(dump, "route replace blackhole default") {
		t.Errorf("the missing floor was not installed:\n%s", dump)
	}
	for _, a := range acts {
		// Only the rule that moves clients: the 390 exemptions and the in-namespace
		// tproxy rule are a different question, and this world does not model them.
		if a.Changes() && strings.Contains(a.Display, "ip rule ") &&
			(strings.Contains(a.Display, "pref 400") || strings.Contains(a.Display, "lookup 51822")) {
			t.Errorf("installing the floor tore down a working rule: %s", a.Display)
		}
	}
}

func displays(acts []reconcile.Action) string {
	var b strings.Builder
	for _, a := range acts {
		b.WriteString(a.Display + "\n")
	}
	return b.String()
}

// A blackhole at somebody else's metric is not this floor. It would satisfy a
// substring check and then never be corrected — and the metric is the whole reason
// the veth route wins while the veth is up.
func TestAFloorAtTheWrongMetricIsNotTakenForOurs(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		if strings.Contains(line, "route show table 51822") {
			return "default via 100.127.255.2 dev mih-host\nblackhole default metric 5\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{run: run, clientIface: "wg0"}
	if p.floorLive(context.Background(), run, "51822") {
		t.Error("a blackhole at metric 5 was accepted as the floor this build installs")
	}
}

// The rule that sends clients into the namespace must not be installed over a
// table its own predecessors failed to fill. Both of those steps are best-effort,
// so their failure is a warning and the pass continues — which is precisely how a
// rule ends up pointing at nothing.
func TestTheMoveRuleRefusesAnUnusableTable(t *testing.T) {
	cases := map[string]string{
		"nothing at all":     "",
		"floor but no route": "blackhole default metric 1000\n",
		"route but no floor": "default via 100.127.255.2 dev mih-host\n",
	}
	for name, table := range cases {
		t.Run(name, func(t *testing.T) {
			run := func(_ context.Context, cmd string, args ...string) (string, error) {
				if strings.Contains(cmd+" "+strings.Join(args, " "), "route show table 51822") {
					return table, nil
				}
				return "", errors.New("absent")
			}
			p := netnsPlanner{run: run, clientIface: "wg0"}
			if p.tableUsable(context.Background(), run, "51822", "100.127.255.2", "mih-host") {
				t.Errorf("the rule would have been installed over a table that reads %q", table)
			}
		})
	}
	full := "default via 100.127.255.2 dev mih-host\nblackhole default metric 1000\n"
	run := func(_ context.Context, cmd string, args ...string) (string, error) {
		if strings.Contains(cmd+" "+strings.Join(args, " "), "route show table 51822") {
			return full, nil
		}
		return "", errors.New("absent")
	}
	p := netnsPlanner{run: run, clientIface: "wg0"}
	if !p.tableUsable(context.Background(), run, "51822", "100.127.255.2", "mih-host") {
		t.Error("a table with both the route and the floor was refused")
	}
}

// A stopped mihomo is usually nothing to worry about: compose starts it, and it
// joins the holder's namespace on the way up. That is true only while the ID
// compose stored still belongs to the live holder.
//
// `network_mode: container:X` is resolved at CREATE time, so a holder that was
// removed and recreated leaves mihomo pointing at an ID that no longer exists.
// `docker compose up -d` then STARTS the existing container instead of recreating
// it, the start fails with "cannot join network of a non running container", and
// it fails that way forever — the only command that fixes it is the
// --force-recreate this gate decides on.
func TestAStoppedMihomoPointingAtADeadHolderIsRecreated(t *testing.T) {
	const liveHolder = "9fb7f48a1528fbabd3a3a614c61686c80515a8bbbe437060a1ca58ba005077f7"
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "{{.State.Pid}} mihomo"):
			return "0\n", nil // stopped
		case strings.Contains(line, "{{.Id}} wgfleet-netns"):
			return liveHolder + "\n", nil
		case strings.Contains(line, "{{.HostConfig.NetworkMode}} mihomo"):
			return "container:0000000000000000000000000000000000000000000000000000000000000000\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{run: run, composePath: "/etc/wgfleet/docker-compose.yml"}
	if p.mihomoIsInTheNamespace(context.Background(), "/proc/4242/ns/net", run) {
		t.Error("a mihomo bound to a holder that no longer exists was reported as fine, " +
			"so the only command that could fix it is never rendered")
	}
}

// And a stopped mihomo that still names the live holder is left alone: recreating
// it costs every client connection it holds.
func TestAStoppedMihomoPointingAtTheLiveHolderIsLeftAlone(t *testing.T) {
	const liveHolder = "9fb7f48a1528fbabd3a3a614c61686c80515a8bbbe437060a1ca58ba005077f7"
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "{{.State.Pid}} mihomo"):
			return "0\n", nil
		case strings.Contains(line, "{{.Id}} wgfleet-netns"):
			return liveHolder + "\n", nil
		case strings.Contains(line, "{{.HostConfig.NetworkMode}} mihomo"):
			return "container:" + liveHolder + "\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := netnsPlanner{run: run, composePath: "/etc/wgfleet/docker-compose.yml"}
	if !p.mihomoIsInTheNamespace(context.Background(), "/proc/4242/ns/net", run) {
		t.Error("a stopped mihomo that still names the live holder was bounced for no reason")
	}
}

// A question we could not ask stays "yes". The cost of a wrong "no" here is every
// client connection mihomo holds, and an unreadable docker is not evidence.
func TestAnUnreadableDockerDoesNotBounceMihomo(t *testing.T) {
	run := func(context.Context, string, ...string) (string, error) {
		return "", errors.New("docker daemon is not answering")
	}
	p := netnsPlanner{run: run, composePath: "/etc/wgfleet/docker-compose.yml"}
	if !p.mihomoIsInTheNamespace(context.Background(), "/proc/4242/ns/net", run) {
		t.Error("an unanswerable question was read as a fault")
	}
}
