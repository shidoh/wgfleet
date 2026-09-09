package exit

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/dockerfw"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// lifelinePeer mints one reserve peer. The addresses are lifeline-pool /32s, the
// shape LifelinePeersOf produces, and every peer carries a PRESHARED KEY because
// every real one does: the lifeline derives one per exit from the credential's
// own (ADR-0034). A helper that left it empty tested a peer the fleet never
// issues, and hid the fact that a peer edit used to refuse them and bounce the
// device instead.
func lifelinePeer(t *testing.T, name, addr string) domain.WGClientPeer {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	return domain.WGClientPeer{Name: name, PublicKey: kp.PublicKey, Address: addr, PresharedKey: psk}
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
	p := lifelinePlannerFor(t, false) // no config, and no interface either

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

// Disabling the lifeline converges in TWO passes, and the order is the whole
// point: the config is what `awg-quick down` reads to find the interface, so
// deleting it while awgl0 is still up strands a live interface nothing can take
// down and nothing is watching — the spec is gone, so the health check is gone
// with it. First pass brings it down and KEEPS the config; only a pass that finds
// the interface actually gone removes it.
func TestLifelineDisabledBringsTheInterfaceDownBeforeRemovingItsConfig(t *testing.T) {
	p := lifelinePlannerFor(t, true)
	applyLifeline(t, p, lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32")))
	if _, err := os.Stat(p.confPath); err != nil {
		t.Fatalf("setup: the config was not rendered: %v", err)
	}
	disabled := domain.NodeSpec{Role: domain.RoleExit}

	// Pass 1 — the interface is still up: bring it down, keep the config.
	acts := mustLifelinePlan(t, p, disabled)
	got := planDump(acts)
	if !strings.Contains(got, "awg-quick down "+p.confPath) {
		t.Errorf("disabling the lifeline must bring %s down:\n%s", domain.LifelineInterface, got)
	}
	for _, a := range acts {
		if a.Kind == reconcile.ActionDelete && a.Target == p.confPath {
			t.Fatalf("the config must survive while the interface is up — deleting it orphans %s:\n%s",
				domain.LifelineInterface, got)
		}
	}

	// Pass 2 — the interface is gone: now the config may go.
	p.up = func(string) bool { return false }
	acts = mustLifelinePlan(t, p, disabled)
	var removed bool
	for _, a := range acts {
		if a.Kind == reconcile.ActionDelete && a.Target == p.confPath {
			removed = true
		}
	}
	if !removed {
		t.Errorf("once the interface is down the config must be removed:\n%s", planDump(acts))
	}
}

// A config that has been lost (a wiped /etc, a half-finished restore) with the
// interface still up is the same orphan by another route: there is no config for
// `awg-quick down` to read, so the interface has to be deleted directly.
func TestLifelineDisabledDeletesAnOrphanedInterface(t *testing.T) {
	p := lifelinePlannerFor(t, true) // up, and nothing was ever written to confPath
	got := planDump(mustLifelinePlan(t, p, domain.NodeSpec{Role: domain.RoleExit}))
	if !strings.Contains(got, "ip link del "+domain.LifelineInterface) {
		t.Errorf("an interface with no config must still be torn down:\n%s", got)
	}
}

// A stale deferral from a lifeline that no longer exists is a reason for a
// decision nobody is making any more.
func TestLifelineDisabledClearsAStaleDeferral(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	keyless := p
	keyless.privateKey = ""
	applyActions(t, mustLifelinePlan(t, keyless, lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32"))))
	if _, err := os.Stat(p.confPath + ".deferred"); err != nil {
		t.Fatalf("setup: no deferral was recorded: %v", err)
	}

	applyActions(t, mustLifelinePlan(t, p, domain.NodeSpec{Role: domain.RoleExit}))
	if _, err := os.Stat(p.confPath + ".deferred"); !os.IsNotExist(err) {
		t.Errorf("a lifeline that is gone must not leave its deferral behind (err=%v)", err)
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
	if strings.Contains(got, bob.PresharedKey) {
		t.Fatalf("the peer's preshared key leaked into the plan:\n%s", got)
	}
}

// And revoking one must not cost the others either — the same argument, run the
// other way. This is the case that used to bounce the device unconditionally.
func TestLifelineRemovingAPeerPatchesInsteadOfBouncing(t *testing.T) {
	p := lifelinePlannerFor(t, true)
	alice := lifelinePeer(t, "alice", "10.98.77.7/32")
	bob := lifelinePeer(t, "bob", "10.98.77.9/32")
	applyLifeline(t, p, lifelineNodeSpec(alice, bob))
	p.ifacePeers = func(string) ([]string, error) { return []string{alice.PublicKey, bob.PublicKey}, nil }

	got := planDump(mustLifelinePlan(t, p, lifelineNodeSpec(alice)))
	if strings.Contains(got, "bring the lifeline interface down") {
		t.Fatalf("revoking one credential took the whole lifeline down:\n%s", got)
	}
	if !strings.Contains(got, "awg set "+domain.LifelineInterface+" peer "+bob.PublicKey+" remove") {
		t.Fatalf("the revoked peer is never removed from the live lifeline:\n%s", got)
	}
}

// A converged lifeline is silent: no re-render, no bounce.
func TestLifelineSecondPassIsNoChange(t *testing.T) {
	p := lifelinePlannerFor(t, true)
	alice := lifelinePeer(t, "alice", "10.98.77.7/32")
	spec := lifelineNodeSpec(alice)
	applyLifeline(t, p, spec)
	// awg-quick cannot run on a dev box, so the bring-up "failed" and left its
	// marker behind. Stand in for the success the next pass would have had.
	_ = os.Remove(p.confPath + ".deferred")
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

// Once the interface is CONVERGED — up, on the rendered config, serving exactly the
// spec's peers — the deferral marker must go: a stale reason on disk is a health
// check reporting a problem that has been fixed.
func TestLifelineClearsTheDeferralOnceItHasConverged(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	alice := lifelinePeer(t, "alice", "10.98.77.7/32")
	spec := lifelineNodeSpec(alice)
	keyless := p
	keyless.privateKey = ""
	applyActions(t, mustLifelinePlan(t, keyless, spec))
	if _, err := os.Stat(p.confPath + ".deferred"); err != nil {
		t.Fatalf("setup: no deferral was recorded: %v", err)
	}

	applyLifeline(t, p, spec)
	// awg-quick cannot run here, so stand in for the bring-up having worked: the
	// interface is up and serving the spec's peers.
	converged := p
	converged.up = func(string) bool { return true }
	converged.ifacePeers = func(string) ([]string, error) { return []string{alice.PublicKey}, nil }
	applyActions(t, mustLifelinePlan(t, converged, spec))
	if _, err := os.Stat(p.confPath + ".deferred"); !os.IsNotExist(err) {
		t.Errorf("the deferral marker must be cleared once the interface has converged (err=%v)", err)
	}
}

// And until then it must STAY. Both awg-quick steps are best-effort — a failure is
// a log line, not an aborted pass — so a bounce that did not work leaves the
// interface up on its previous config, serving a peer list that is no longer the
// spec's. `ip link show` cannot tell that apart from health; the marker can, and
// clearing it alongside the config write (as this planner used to) disarmed the
// only signal that reports it, in the pass that most needed it.
func TestLifelineFailedBringUpLeavesTheDeferralForTheHealthCheck(t *testing.T) {
	p := lifelinePlannerFor(t, false)
	spec := lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32"))

	applyLifeline(t, p, spec) // awg-quick does not exist here: the bring-up fails
	reason, err := os.ReadFile(p.confPath + ".deferred")
	if err != nil {
		t.Fatalf("a failed bring-up must leave a reason behind for the check to read: %v", err)
	}
	if !strings.Contains(string(reason), "did not complete") {
		t.Errorf("the recorded reason does not say the apply failed: %q", reason)
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

// --- the lifeline pool in the rest of the exit's data plane ---

// lifelineExitSpec is a full exit spec (firewall, routing, DNS) that also carries
// a lifeline, i.e. what the controller sends once the operator flips the knob.
func lifelineExitSpec(t *testing.T) domain.NodeSpec {
	t.Helper()
	spec, _ := exitSpec(t)
	ll := lifelineNodeSpec(lifelinePeer(t, "alice", "10.98.77.7/32")).Lifeline
	spec.Lifeline = ll
	// The controller opens the hole and describes the interface together; netfw
	// refuses one without the other, because either alone is a misconfiguration.
	spec.Firewall.LifelinePort = ll.ListenPort
	return spec
}

// The lifeline pool needs its own hole, its own masquerade and its own forward
// pair. Without them the interface comes up and every packet on it dies: the
// listener is firewalled off, and what does get through leaves with a private
// source address.
func TestFirewallCarriesTheLifelinePool(t *testing.T) {
	acts, err := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), lifelineExitSpec(t))
	if err != nil {
		t.Fatalf("a lifeline exit's ruleset must render: %v", err)
	}
	iface := "\"" + domain.LifelineInterface + "\""
	for _, want := range []string{
		"udp dport 41827 accept", // the lifeline listener
		// SNAT out of the reserve pool, and the guard that asserts nothing leaves
		// still carrying it — both scoped to the lifeline's own interface.
		"ip saddr 10.98.77.0/24 oifname != " + iface + " masquerade",
		"ip saddr 10.98.77.0/24 ip saddr != 10.98.77.1 oifname != " + iface,
	} {
		if !strings.Contains(acts[0].Display, want) {
			t.Errorf("lifeline exit ruleset missing %q:\n%s", want, acts[0].Display)
		}
	}
}

// An exit without a lifeline must render exactly as it did before: no pool, no
// interface, and — since netfw refuses a hole without a listener — no port.
func TestFirewallLeavesTheLifelineOutWhenTheSpecHasNone(t *testing.T) {
	spec, _ := exitSpec(t)
	acts, err := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(acts[0].Display, domain.LifelineInterface) {
		t.Errorf("an exit with no lifeline must not render one:\n%s", acts[0].Display)
	}
}

// A WARP lifeline egresses through WARP like the exit's primary pool, so its
// traffic needs the same policy-routing rule. Without it the reserve clients'
// packets follow the host default route and leave with the exit's own address,
// which is the leak an earlier finding is about.
func TestRoutingSendsTheLifelinePoolToTheEgressTable(t *testing.T) {
	spec := lifelineExitSpec(t)
	acts, err := routingPlanner{statePath: testPaths(t).RoutingState}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planDump(acts), "from 10.98.77.0/24 lookup") {
		t.Errorf("a WARP lifeline's pool must be policy-routed to the egress table:\n%s", planDump(acts))
	}
}

// A lifeline that egresses DIRECTLY must not be policy-routed into WARP, even on
// an exit whose primary pool is. The two pools are separately switchable on
// purpose: the reserve leg is the one that has to keep working when the egress
// the primary pool uses is what got blocked.
func TestRoutingLeavesADirectLifelineAlone(t *testing.T) {
	spec := lifelineExitSpec(t)
	direct := *spec.Lifeline
	direct.Egress = domain.EgressDirect
	spec.Lifeline = &direct

	acts, err := routingPlanner{statePath: testPaths(t).RoutingState}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planDump(acts), "10.98.77.0/24") {
		t.Errorf("a direct-egress lifeline must not be routed into WARP:\n%s", planDump(acts))
	}
}

// Reserve clients are handed the lifeline gateway as their resolver, so blocky
// has to bind it. Until it does, every client that falls back to the lifeline has
// a DNS server that does not answer — a tunnel that comes up and resolves nothing.
func TestDNSFilterBindsTheLifelineGateway(t *testing.T) {
	dir := t.TempDir()
	p := dnsPlanner{
		configPath:  filepath.Join(dir, "config.yml"),
		composePath: filepath.Join(dir, "docker-compose.yml"),
		up:          func(string) bool { return true },
	}
	acts, err := p.Plan(context.Background(), lifelineExitSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planDump(acts), "10.98.77.1:53") {
		t.Errorf("blocky must bind the lifeline gateway:\n%s", planDump(acts))
	}
}

// Docker sets the FORWARD policy to DROP, so a lifeline missing from DOCKER-USER
// black-holes silently between two interfaces the operator never configured
// — while every nftables rule the agent renders looks right.
func TestDockerUserAcceptsLifelineForwarding(t *testing.T) {
	paths := testPaths(t)
	want := dockerfw.NewForwardPlanner(
		"exit forwarding (ip_forward + DOCKER-USER)",
		"awg0", "awg0",
		"accept client→egress forwarding (DOCKER-USER)",
		domain.LifelineInterface)

	var found bool
	for _, pl := range Planners(Input{Paths: paths}) {
		fp, ok := pl.(dockerfw.ForwardPlanner)
		if !ok {
			continue
		}
		found = true
		if !reflect.DeepEqual(fp, want) {
			t.Errorf("the exit's DOCKER-USER planner must also allow %s:\ngot  %+v\nwant %+v",
				domain.LifelineInterface, fp, want)
		}
	}
	if !found {
		t.Fatal("no DOCKER-USER forwarding planner in the exit plan")
	}
}

// blocky is a host-net container under Docker's restart policy, so after a reboot
// it can (re)start before the agent has raised awgl0 — and the lifeline gateway it
// is told to bind does not exist yet. Without ip_nonlocal_bind that is a crash
// loop: the resolver the reserve clients depend on is down for as long as Docker's
// backoff lasts. The master pays for exactly the same race on wg0 and solves it
// the same way.
func TestDNSFilterAllowsBindingTheLifelineGatewayBeforeItExists(t *testing.T) {
	plannerIn := func(dir string, bound bool) dnsPlanner {
		return dnsPlanner{
			configPath:   filepath.Join(dir, "config.yml"),
			composePath:  filepath.Join(dir, "docker-compose.yml"),
			sysctlPath:   filepath.Join(dir, "99-wgfleet-nonlocal-bind.conf"),
			up:           func(string) bool { return true },
			nonlocalBind: func() bool { return bound },
		}
	}
	const sysctl = "net.ipv4.ip_nonlocal_bind=1"

	// A lifeline gateway to bind, and the sysctl off ⇒ turn it on.
	acts, err := plannerIn(t.TempDir(), false).Plan(context.Background(), lifelineExitSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planDump(acts), sysctl) {
		t.Errorf("a lifeline exit must allow binding the not-yet-present gateway:\n%s", planDump(acts))
	}

	// Already on ⇒ a no-change, not a perpetual "change" every pass.
	acts, err = plannerIn(t.TempDir(), true).Plan(context.Background(), lifelineExitSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planDump(acts), sysctl) {
		t.Errorf("ip_nonlocal_bind is already on; the planner must not re-set it:\n%s", planDump(acts))
	}
	if !strings.Contains(summariesOf(acts), "already enabled") {
		t.Errorf("the satisfied precondition should still be visible in the plan:\n%s", summariesOf(acts))
	}

	// No lifeline ⇒ no gateway to bind, and the exit's plan must be exactly what it
	// was before this existed: blocky binds only loopback and the mgmt address,
	// both of which are there before it starts.
	spec, _ := exitSpec(t)
	acts, err = plannerIn(t.TempDir(), false).Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planDump(acts), "ip_nonlocal_bind") {
		t.Errorf("an exit without a lifeline must not touch ip_nonlocal_bind:\n%s", planDump(acts))
	}
}

// --- the resolver reserve clients are handed ---

// lifelineRuleset plans the exit firewall and returns the rendered ruleset.
func lifelineRuleset(t *testing.T, spec domain.NodeSpec) string {
	t.Helper()
	acts, err := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return acts[0].Display
}

// With no explicit lifeline.dns the controller hands reserve clients the lifeline
// gateway as their resolver and the exit's own blocky binds it — so the query
// arrives on this node's INPUT hook, where the drop policy eats it unless the
// resolver ports are open on the reserve interface. Plain DNS and DoT both:
// clients dial :853 regardless of the bare-IP nameserver they were given.
func TestFirewallOpensTheResolverToReserveClients(t *testing.T) {
	out := lifelineRuleset(t, lifelineExitSpec(t))
	iface := "\"" + domain.LifelineInterface + "\""
	for _, want := range []string{
		"iifname " + iface + " udp dport 53 accept",
		"iifname " + iface + " tcp dport 53 accept",
		"iifname " + iface + " tcp dport 853 accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lifeline exit ruleset missing %q:\n%s", want, out)
		}
	}
}

// The holes follow the resolver's actual ports, not the defaults: an operator who
// moved plain DNS gets the port they moved it to, and one who turned DoT off gets
// no 853 hole at all.
func TestFirewallResolverHolesFollowTheConfiguredPorts(t *testing.T) {
	spec := lifelineExitSpec(t)
	spec.DNS.Ports = domain.DNSPorts{DNS: 5353, TLS: -1}
	out := lifelineRuleset(t, spec)
	if !strings.Contains(out, "udp dport 5353 accept") {
		t.Errorf("the plain-DNS hole must follow the configured port:\n%s", out)
	}
	if strings.Contains(out, "dport 853 accept") {
		t.Errorf("DoT is off on this exit: no 853 hole may render:\n%s", out)
	}
}

// An exit that runs no resolver has nothing on those ports, so opening them would
// be exposure for nothing.
func TestFirewallOpensNoResolverWhenTheFilterIsOff(t *testing.T) {
	spec := lifelineExitSpec(t)
	spec.DNS.Enabled = false
	out := lifelineRuleset(t, spec)
	for _, unwanted := range []string{"dport 53 accept", "dport 853 accept"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("no resolver on this exit: ruleset must not carry %q:\n%s", unwanted, out)
		}
	}
}

// And an exit without a lifeline renders no resolver hole either, however healthy
// its blocky is: the accepts exist for the reserve pool alone.
func TestFirewallOpensNoResolverWithoutALifeline(t *testing.T) {
	spec, _ := exitSpec(t)
	out := lifelineRuleset(t, spec)
	for _, unwanted := range []string{"dport 53 accept", "dport 853 accept"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("no lifeline: ruleset must not carry %q:\n%s", unwanted, out)
		}
	}
}

// A running kernel is not a persisted one. `sysctl -w` is gone after a reboot,
// and a reboot is exactly when the ordering goes wrong: blocky's container can
// start before the agent's first pass raises awgl0, fail to bind the gateway, and
// leave every reserve client without DNS on a node whose dns-filter check is
// green — that check probes the mgmt address, which is always there. So the
// setting is written as a sysctl.d drop-in, and only on an exit that has a
// gateway to bind.
func TestDNSFilterPersistsNonlocalBindAcrossAReboot(t *testing.T) {
	dir := t.TempDir()
	sysctlPath := filepath.Join(dir, "99-wgfleet-nonlocal-bind.conf")
	p := dnsPlanner{
		configPath:   filepath.Join(dir, "config.yml"),
		composePath:  filepath.Join(dir, "docker-compose.yml"),
		sysctlPath:   sysctlPath,
		up:           func(string) bool { return true },
		nonlocalBind: func() bool { return true }, // already on in THIS kernel
	}
	acts, err := p.Plan(context.Background(), lifelineExitSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planDump(acts), "net.ipv4.ip_nonlocal_bind = 1") {
		t.Fatalf("the running value is set but never persisted:\n%s", planDump(acts))
	}
	var written bool
	for _, a := range acts {
		if a.Target == sysctlPath {
			written = true
		}
	}
	if !written {
		t.Fatalf("the drop-in is not written to sysctl.d:\n%s", planDump(acts))
	}
}

// An exit with no lifeline has no gateway to bind, so it must not turn a
// system-wide sysctl on — nor leave a drop-in behind claiming it should be.
func TestDNSFilterWritesNoSysctlDropInWithoutALifeline(t *testing.T) {
	dir := t.TempDir()
	spec, _ := exitSpec(t)
	spec.DNS.Enabled, spec.DNS.MgmtAddr = true, "10.20.0.9"
	p := dnsPlanner{
		configPath:   filepath.Join(dir, "config.yml"),
		composePath:  filepath.Join(dir, "docker-compose.yml"),
		sysctlPath:   filepath.Join(dir, "99-wgfleet-nonlocal-bind.conf"),
		up:           func(string) bool { return true },
		nonlocalBind: func() bool { return false },
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planDump(acts), "nonlocal_bind") {
		t.Fatalf("an exit without a lifeline must not touch ip_nonlocal_bind:\n%s", planDump(acts))
	}
}
