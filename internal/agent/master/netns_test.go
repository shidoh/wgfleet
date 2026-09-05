package master

import (
	"context"
	"errors"
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

// An unset knob is the same as "off" for now: the fleet that swaps a binary must
// keep the path it had until the migration has been exercised end to end.
func TestNetnsPlannerIsInertWhenTheKnobIsUnset(t *testing.T) {
	spec := netnsSpec()
	spec.Master.ClientViaNetns = ""
	acts, err := netnsPlanner{run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("an unconfigured master probed the box for a namespace")
		return "", nil
	}}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("an unconfigured master would change %q", a.Summary)
		}
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
