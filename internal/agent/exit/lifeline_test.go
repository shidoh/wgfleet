package exit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// lifelinePeer mints one reserve peer. The addresses are lifeline-pool /32s, the
// shape LifelinePeersOf produces.
func lifelinePeer(t *testing.T, name, addr string) domain.WGClientPeer {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return domain.WGClientPeer{Name: name, PublicKey: kp.PublicKey, Address: addr}
}

// lifelineNodeSpec is an exit spec carrying a lifeline interface on the reserve
// pool. 41827 and 10.98.77.0/24 are the documented lifeline defaults.
func lifelineNodeSpec(peers ...domain.WGClientPeer) domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleExit,
		Lifeline: &domain.LifelineSpec{
			ClientWGSpec: domain.ClientWGSpec{
				ListenPort:    41827,
				AddressPool:   "10.98.77.0/24",
				ServerAddress: "10.98.77.1",
				MTU:           1380,
				DNS:           []string{"10.98.77.1"},
				AllowedIPs:    []string{"0.0.0.0/0"},
				Backend:       domain.ClientWGBackendKernel,
				Clients:       peers,
			},
			Egress: domain.EgressWARP,
		},
	}
}

func lifelinePlannerFor(t *testing.T, up bool) lifelinePlanner {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return lifelinePlanner{
		confPath:   filepath.Join(t.TempDir(), domain.LifelineInterface+".conf"),
		privateKey: kp.PrivateKey,
		up:         func(string) bool { return up },
	}
}

func mustLifelinePlan(t *testing.T, p lifelinePlanner, spec domain.NodeSpec) []reconcile.Action {
	t.Helper()
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	return acts
}

func applyLifeline(t *testing.T, p lifelinePlanner, spec domain.NodeSpec) {
	t.Helper()
	// The awg-quick execs fail on a dev box, which is expected: the FileAction runs
	// first, so the rendered config lands on disk either way.
	eng := reconcile.NewEngine(nil, p)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
}

// An exit without a lifeline and without a config file has nothing to say. Most
// exits are in this state, and a planner that reported work every pass would make
// the plan output useless for the exits that do carry one.
func TestLifelineAbsentAndUnconfiguredIsQuiet(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	acts := mustLifelinePlan(t, p, domain.NodeSpec{Role: domain.RoleExit})
	for _, a := range acts {
		if a.Changes() {
			t.Fatalf("an exit with no lifeline must plan no changes, got %+v", acts)
		}
	}
	if !strings.Contains(summariesOf(acts), "not configured") {
		t.Fatalf("plan should say the lifeline is not configured:\n%s", summariesOf(acts))
	}
}

// Clearing the manifest knob must actually take the interface down. The config
// file on disk is the ownership evidence — nothing but the agent raises awgl0 —
// so its presence is what distinguishes "disable it" from "never had one".
func TestLifelineDisabledBringsTheInterfaceDownAndRemovesTheConfig(t *testing.T) {
	p := lifelinePlannerFor(t, true)
	applyLifeline(t, p, lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32")))
	if _, err := os.Stat(p.confPath); err != nil {
		t.Fatalf("setup: the config was not rendered: %v", err)
	}

	acts := mustLifelinePlan(t, p, domain.NodeSpec{Role: domain.RoleExit})
	got := planDump(acts)
	if !strings.Contains(got, "awg-quick down "+p.confPath) {
		t.Errorf("disabling the lifeline must bring %s down:\n%s", domain.LifelineInterface, got)
	}
	var removed bool
	for _, a := range acts {
		if a.Kind == reconcile.ActionDelete && a.Target == p.confPath {
			removed = true
		}
	}
	if !removed {
		t.Errorf("disabling the lifeline must remove its config:\n%s", got)
	}
}

// The rendered interface is what an operator would have written by hand: the
// lifeline port, the lifeline gateway, and every reserve peer — at 0600, because
// it carries the interface private key.
func TestLifelineRendersTheReserveInterface(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	peer := lifelinePeer(t, "alice", "10.98.77.7/32")
	spec := lifelineNodeSpec(peer)

	if !strings.Contains(summariesOf(mustLifelinePlan(t, p, spec)), "bring the lifeline interface up") {
		t.Fatalf("a lifeline that is down must be raised:\n%s", summariesOf(mustLifelinePlan(t, p, spec)))
	}

	applyLifeline(t, p, spec)
	data, err := os.ReadFile(p.confPath)
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	cfg := string(data)
	for _, want := range []string{
		"[Interface]", "ListenPort = 41827", "Address = 10.98.77.1/24",
		"MTU = 1380", "[Peer]", peer.PublicKey, "10.98.77.7/32",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered lifeline config missing %q:\n%s", want, cfg)
		}
	}
	info, err := os.Stat(p.confPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("lifeline config mode = %v, want 0600 (it holds the private key)", info.Mode().Perm())
	}
}

// Issuing one credential must not cost every established lifeline session. The
// lifeline is the fleet's reserve path; bouncing the device to add a peer would
// disconnect exactly the people who are on it because the master is unreachable.
func TestLifelineAddingAPeerPatchesInsteadOfBouncing(t *testing.T) {
	p := lifelinePlannerFor(t, true)
	alice := lifelinePeer(t, "alice", "10.98.77.7/32")
	applyLifeline(t, p, lifelineNodeSpec(alice))
	p.ifacePeers = func(string) ([]string, error) { return []string{alice.PublicKey}, nil }

	bob := lifelinePeer(t, "bob", "10.98.77.9/32")
	got := planDump(mustLifelinePlan(t, p, lifelineNodeSpec(alice, bob)))
	if strings.Contains(got, "bring the lifeline interface down") {
		t.Fatalf("adding one peer took the whole lifeline down:\n%s", got)
	}
	if !strings.Contains(got, "awg set "+domain.LifelineInterface+" peer "+bob.PublicKey) {
		t.Fatalf("the new peer never reaches the live lifeline:\n%s", got)
	}
}

// A converged lifeline is silent: no re-render, no bounce.
func TestLifelineSecondPassIsNoChange(t *testing.T) {
	p := lifelinePlannerFor(t, true)
	alice := lifelinePeer(t, "alice", "10.98.77.7/32")
	spec := lifelineNodeSpec(alice)
	applyLifeline(t, p, spec)
	p.ifacePeers = func(string) ([]string, error) { return []string{alice.PublicKey}, nil }

	for _, a := range mustLifelinePlan(t, p, spec) {
		if a.Changes() {
			t.Fatalf("a converged lifeline must plan no changes, got %q (%v)", a.Summary, a.Kind)
		}
	}
}

// Without a key there is no interface anyone can authenticate against. Defer with
// a reason on disk rather than render a config that serves nobody.
func TestLifelineDefersWithoutAPrivateKey(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	p.privateKey = ""
	acts := mustLifelinePlan(t, p, lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32")))
	if !strings.Contains(summariesOf(acts), "pending") {
		t.Fatalf("a keyless lifeline must defer:\n%s", summariesOf(acts))
	}
	applyActions(t, acts)
	if _, err := os.Stat(p.confPath); err == nil {
		t.Error("a deferred pass must not write an interface config")
	}
	if _, err := os.Stat(p.confPath + ".deferred"); err != nil {
		t.Errorf("the deferral reason must be recorded where the status page can find it: %v", err)
	}
}

// An AmneziaWG 3.x lifeline on a 1.x module would be rejected by `awg setconf`,
// and awg-quick would leave the interface down. Refuse before writing anything,
// keeping the last-good config — and, unlike the exit's own WGServer planner, do
// NOT fail the pass: the lifeline is a reserve, and failing here would stop the
// firewall, routing and egress planners behind it from converging.
func TestLifelineDefersWhenAWG3IsUnsupported(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	p.awgGen = func() (int, error) { return 1, nil }
	spec := lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32"))
	awg := *awg3Spec().WGServer.AWG
	spec.Lifeline.AWG = &awg

	acts := mustLifelinePlan(t, p, spec)
	if !strings.Contains(summariesOf(acts), "AmneziaWG 3.x refused") {
		t.Fatalf("a 3.x lifeline on a 1.x module must be refused:\n%s", summariesOf(acts))
	}
	applyActions(t, acts)
	if _, err := os.Stat(p.confPath); err == nil {
		t.Error("the planner must not write a config it knows cannot be applied")
	}
	reason, err := os.ReadFile(p.confPath + ".deferred")
	if err != nil {
		t.Fatalf("the refusal must be recorded: %v", err)
	}
	if !strings.Contains(string(reason), "3.0") {
		t.Errorf("the recorded reason should name the module problem, got %q", reason)
	}
}

// A 3.x module carries a 3.x lifeline: the gate must not refuse the happy path.
func TestLifelineAppliedOnAModernModule(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	p.awgGen = func() (int, error) { return 3, nil }
	spec := lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32"))
	awg := *awg3Spec().WGServer.AWG
	spec.Lifeline.AWG = &awg

	if got := summariesOf(mustLifelinePlan(t, p, spec)); !strings.Contains(got, "bring the lifeline interface up") {
		t.Fatalf("a 3.x lifeline on a 3.x module must be raised:\n%s", got)
	}
}

// A spec the interface renderer would reject must not fail the pass either: the
// last-good config keeps serving and every other exit planner keeps converging.
func TestLifelineDefersOnAnInvalidSpec(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	spec := lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32"))
	spec.Lifeline.ServerAddress = "10.90.0.1" // outside the lifeline pool

	acts := mustLifelinePlan(t, p, spec)
	if !strings.Contains(summariesOf(acts), "spec rejected") {
		t.Fatalf("an invalid lifeline spec must defer, not fail:\n%s", summariesOf(acts))
	}
	applyActions(t, acts)
	if _, err := os.Stat(p.confPath); err == nil {
		t.Error("a rejected spec must not be written")
	}
}

// Once the planner applies again, the deferral marker must go: a stale reason on
// disk is a health check reporting a problem that has been fixed.
func TestLifelineClearsTheDeferralOnceItApplies(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	spec := lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32"))
	keyless := p
	keyless.privateKey = ""
	applyActions(t, mustLifelinePlan(t, keyless, spec))
	if _, err := os.Stat(p.confPath + ".deferred"); err != nil {
		t.Fatalf("setup: no deferral was recorded: %v", err)
	}

	applyLifeline(t, p, spec)
	if _, err := os.Stat(p.confPath + ".deferred"); !os.IsNotExist(err) {
		t.Errorf("the deferral marker must be cleared once the planner applies (err=%v)", err)
	}
}

// Order is load-bearing: the lifeline is a client-facing interface like the exit's
// own AWG server, and it must exist before the WARP egress and the routing that
// send its pool out. Ordering it after wgPlanner keeps the two interface planners
// together; ordering it before warpPlanner keeps the egress behind it.
func TestPlannersRaiseTheLifelineBetweenTheServerAndWARP(t *testing.T) {
	paths := testPaths(t)
	paths.LifelineConf = filepath.Join(filepath.Dir(paths.WGConf), domain.LifelineInterface+".conf")
	var order []string
	for _, pl := range Planners(Input{Paths: paths}) {
		order = append(order, pl.Component())
	}
	idx := func(want string) int {
		for i, c := range order {
			if c == want {
				return i
			}
		}
		t.Fatalf("no %q planner in %v", want, order)
		return -1
	}
	if wgIdx, llIdx, warpIdx := idx("amneziawg interface"), idx("lifeline interface"), idx("warp egress (wgcf)"); !(wgIdx < llIdx && llIdx < warpIdx) {
		t.Fatalf("lifeline must sit after the AWG server and before WARP, got %v", order)
	}
}

// The lifeline is a real interface with real key material, so decommissioning has
// to take it down and wipe both — otherwise a re-provisioned node comes back
// carrying a stale reserve interface keyed to credentials it no longer serves.
func TestExitTeardownTakesTheLifelineDown(t *testing.T) {
	paths := PathsUnder("/tmp/x")
	eng := reconcile.NewEngine(nil, TeardownPlanners(paths)...)
	report, err := eng.Reconcile(context.Background(),
		domain.NodeSpec{Decommission: true, Role: domain.RoleExit}, reconcile.ModePlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(report.String(), "awg-quick down "+paths.LifelineConf) {
		t.Errorf("teardown must bring the lifeline down:\n%s", report.String())
	}
}

func TestExitTeardownWipesTheLifelineKeyAndConfig(t *testing.T) {
	dir := t.TempDir()
	paths := PathsUnder(dir)
	managed := []string{paths.LifelineConf, paths.LifelineKey}
	for _, p := range managed {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	eng := reconcile.NewEngine(nil, TeardownPlanners(paths)...)
	if _, err := eng.Reconcile(context.Background(),
		domain.NodeSpec{Decommission: true, Role: domain.RoleExit}, reconcile.ModeApply); err != nil {
		t.Fatalf("teardown apply aborted: %v", err)
	}
	for _, p := range managed {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("teardown did not wipe %s (err=%v)", p, err)
		}
	}
}

// summariesOf joins action summaries, for assertions about what a plan decided.
func summariesOf(actions []reconcile.Action) string {
	var b strings.Builder
	for _, a := range actions {
		b.WriteString(a.Summary)
		b.WriteString("\n")
	}
	return b.String()
}

// applyActions runs a planner's actions through the engine so the file writes in
// them actually happen (exec steps fail on a dev box and are best-effort).
func applyActions(t *testing.T, actions []reconcile.Action) {
	t.Helper()
	eng := reconcile.NewEngine(nil, staticPlanner{actions})
	_, _ = eng.Reconcile(context.Background(), domain.NodeSpec{}, reconcile.ModeApply)
}

type staticPlanner struct{ actions []reconcile.Action }

func (staticPlanner) Component() string { return "static" }

func (p staticPlanner) Plan(context.Context, domain.NodeSpec) ([]reconcile.Action, error) {
	return p.actions, nil
}
