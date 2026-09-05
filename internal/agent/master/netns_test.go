package master

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

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
	acts, err := netnsPlanner{run: run}.Plan(context.Background(), netnsSpec())
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

// "off" — and, until the rollout finishes, an unset knob — must be completely
// inert: not one probe of the box, not one action.
func TestNetnsPlannerRespectsOff(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "off"
	acts, err := netnsPlanner{run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("a disabled namespace still probed the box")
		return "", nil
	}}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("a disabled namespace would change %q", a.Summary)
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
	acts, err := netnsPlanner{run: run}.Plan(context.Background(), netnsSpec())
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
	acts, err := netnsPlanner{run: run}.Plan(context.Background(), spec)
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
	_, err := netnsPlanner{run: func(context.Context, string, ...string) (string, error) {
		return "", nil
	}}.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("a mistyped knob converged silently")
	}
	if !strings.Contains(err.Error(), "client_via_netns") {
		t.Errorf("the error does not name the knob: %v", err)
	}
}

// The canary was documented, returned by NetnsWanted and then discarded at every
// call site: an operator who set a /32 in the belief that one device was moving
// got the full move. This is the rule that makes the blast radius one device.
func TestCanaryMovesOnlyTheNamedSources(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		if strings.Contains(name+" "+strings.Join(args, " "), "docker inspect") {
			return "4242\n", nil
		}
		return "", errors.New("absent")
	}
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "10.73.0.7/32"
	p := netnsPlanner{
		run:         run,
		attached:    func() bool { return true },
		clientIface: "wg0",
		nftPath:     t.TempDir() + "/netns.nft",
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	if !strings.Contains(dump, "ip rule add from 10.73.0.7/32 iif wg0 lookup 51822 pref 400") {
		t.Fatalf("the canary moved every client instead of the named source:\n%s", dump)
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
	p := netnsPlanner{run: run, attached: func() bool { return false }, clientIface: "wg0"}
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
	p := netnsPlanner{run: run, attached: func() bool { return false }, clientIface: "wg0"}
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
	p := netnsPlanner{run: run, attached: func() bool { return false }, clientIface: "wg0"}
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

// Widening a canary to a full move must actually change the rule. `ip rule list`
// prints the two as `from 10.80.0.7 iif wg0 lookup 51822` and `from all iif wg0
// lookup 51822`, and a gate that compared only the interface and the table read
// them as the same rule — so the last step of every rollout changed nothing and
// said nothing about it. Measured on the stand 2026-09-05.
func TestWideningACanaryReplacesTheRule(t *testing.T) {
	live := map[string]string{
		"ip rule list":              "400:\tfrom 10.80.0.254 iif wg0 lookup 51822\n",
		"ip route show table 51822": "default via 100.127.255.2 dev mih-host\n",
	}
	spec := netnsSpec()
	spec.Master.ClientViaNetns = "auto"
	dump := attachedPlan(t, spec, live)
	if !strings.Contains(dump, "ip rule add iif wg0 lookup 51822 pref 400") {
		t.Errorf("the canary rule was left in place for a full move:\n%s", dump)
	}

	// And the reverse: a canary must replace a full-move rule.
	live["ip rule list"] = "400:\tfrom all iif wg0 lookup 51822\n"
	spec.Master.ClientViaNetns = "10.80.0.254/32"
	dump = attachedPlan(t, spec, live)
	if !strings.Contains(dump, "ip rule add from 10.80.0.254/32 iif wg0 lookup 51822 pref 400") {
		t.Errorf("a full-move rule was left in place for a canary:\n%s", dump)
	}

	// A converged canary is still left alone.
	live["ip rule list"] = "400:\tfrom 10.80.0.254 iif wg0 lookup 51822\n"
	dump = attachedPlan(t, spec, live)
	if strings.Contains(dump, "lookup 51822 pref 400") {
		t.Errorf("a converged canary rule was rebuilt:\n%s", dump)
	}
}
