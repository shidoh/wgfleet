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
		Master:   &domain.MasterSpec{BindAddress: "10.73.0.1"},
	}
}

// The namespace is built by default, because a switch nobody flips is a fix
// nobody gets. Safety comes from the preconditions and the revert, not from
// leaving it off.
func TestNetnsPlannerBuildsTheLinkByDefault(t *testing.T) {
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

// "off" is the only way to decline, and it must be completely inert.
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
