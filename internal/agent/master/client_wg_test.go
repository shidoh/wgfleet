package master

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/health"
	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/awgmod"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func managedSpec(t *testing.T) domain.NodeSpec {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			ClientWG: &domain.ClientWGSpec{
				ListenPort:    443,
				AddressPool:   "10.80.0.0/24",
				ServerAddress: "10.80.0.1",
				MTU:           1360,
				DNS:           []string{"10.80.0.1"},
				AllowedIPs:    []string{"0.0.0.0/0"},
				AWG: &domain.AWGParams{
					Shared: domain.AWGShared{
						S1: 30, S2: 40, S3: 20, S4: 26,
						H1: domain.AWGHeader{Min: 5, Max: 8},
						H2: domain.AWGHeader{Min: 9, Max: 12},
						H3: domain.AWGHeader{Min: 13, Max: 16},
						H4: domain.AWGHeader{Min: 17, Max: 20},
					},
					Local: domain.AWGLocal{Jc: 4, Jmin: 40, Jmax: 70},
				},
				Clients: []domain.WGClientPeer{
					{Name: "laptop", PublicKey: kp.PublicKey, Address: "10.80.0.2/32"},
				},
			},
		},
	}
}

func clientPlanner(t *testing.T, up bool) clientWGPlanner {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return clientWGPlanner{
		confPath:         filepath.Join(t.TempDir(), "wg0.conf"),
		privateKey:       kp.PrivateKey,
		up:               func(string) bool { return up },
		awgGen:           func() (int, error) { return 3, nil },
		containerPresent: func(string) bool { return false },
	}
}

// summaries flattens a plan into its action summaries for readable assertions.
func summaries(actions []reconcile.Action) string {
	var b strings.Builder
	for _, a := range actions {
		b.WriteString(a.Summary)
		b.WriteString("\n")
	}
	return b.String()
}

// applyPlan runs a planner through the engine in apply mode. The awg-quick execs
// fail on a dev box (no interface, no tool), which is fine and expected: the
// FileAction runs first, so the rendered config is on disk either way — the same
// arrangement the exit's routing test relies on.
// claimIt simulates a bring-up that SUCCEEDED on an earlier pass. The claim is
// now written by an OnApplied hook on the awg-quick up action, and `awg-quick`
// does not exist in a test environment — so a test that needs "we already own
// this interface" has to state that directly rather than get it as a side effect
// of planning.
func claimIt(t *testing.T, p clientWGPlanner) {
	t.Helper()
	if err := os.WriteFile(p.claimPath(), []byte(claimContents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func applyPlan(t *testing.T, p clientWGPlanner, spec domain.NodeSpec) {
	t.Helper()
	eng := reconcile.NewEngine(nil, p)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
}

func TestClientWGPlannerRendersAndRaises(t *testing.T) {
	p := clientPlanner(t, false)
	actions, err := p.Plan(context.Background(), managedSpec(t))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(actions)
	if !strings.Contains(got, "bring the client interface up") {
		t.Fatalf("plan does not raise the interface:\n%s", got)
	}
	// Applying the plan must produce a config the operator could run by hand.
	applyPlan(t, p, managedSpec(t))
	data, err := os.ReadFile(p.confPath)
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	cfg := string(data)
	for _, want := range []string{"[Interface]", "ListenPort = 443", "Address = 10.80.0.1/24", "[Peer]"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered config missing %q:\n%s", want, cfg)
		}
	}
	info, err := os.Stat(p.confPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config mode = %o, want 600 (it holds the interface private key)", perm)
	}
}

// An unchanged config on a live interface is the steady state and must report no
// change, not re-run awg-quick every 30 seconds.
func TestClientWGPlannerIdempotent(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	applyPlan(t, p, spec)
	second, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}
	got := summaries(second)
	if strings.Contains(got, "bring the client interface up") {
		t.Fatalf("second pass re-applied an unchanged config:\n%s", got)
	}
	if !strings.Contains(got, "already up") {
		t.Fatalf("second pass did not report a converged interface:\n%s", got)
	}
}

// The interface comes back after a reboot even when the config has not moved.
func TestClientWGPlannerRaisesADownInterface(t *testing.T) {
	p := clientPlanner(t, false)
	spec := managedSpec(t)
	applyPlan(t, p, spec)
	second, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if got := summaries(second); !strings.Contains(got, "interface was down") {
		t.Fatalf("a down interface was not raised:\n%s", got)
	}
}

// wg-easy still owning the leg must leave the agent entirely out of it.
func TestClientWGPlannerNoopsWhenUnmanaged(t *testing.T) {
	p := clientPlanner(t, false)
	actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "wg-easy owns the client leg") {
		t.Fatalf("unmanaged plan = %s", got)
	}
	if _, err := os.Stat(p.confPath); !os.IsNotExist(err) {
		t.Error("an unmanaged planner wrote a config file")
	}
}

// Without the key we would render a config that authenticates nobody: defer.
func TestClientWGPlannerWaitsForItsKey(t *testing.T) {
	p := clientPlanner(t, false)
	p.privateKey = ""
	actions, err := p.Plan(context.Background(), managedSpec(t))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "pending") {
		t.Fatalf("plan = %s, want a pending no-change", got)
	}
}

// The AWG 3.x gate must refuse BEFORE the config is written: writing it and
// running awg-quick would take the client leg down and fail to bring it back.
//
// It refuses by standing still, not by erroring: this planner runs early and the
// engine stops at the first planner error, so failing here would freeze mihomo,
// the master NAT, blocky and the VLESS inbound too.
func TestClientWGPlannerRefusesAWG3OnALegacyModule(t *testing.T) {
	p := clientPlanner(t, true)
	p.awgGen = func() (int, error) { return 1, nil }
	spec := awg3Spec(t)

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v, want a refusal that does not abort the pass", err)
	}
	if got := summaries(actions); !strings.Contains(got, "AmneziaWG 3.x refused") {
		t.Fatalf("plan does not explain the refusal:\n%s", got)
	}
	// The one change a refused pass IS allowed to make: recording why, where the
	// health check can read it. Anything else would be touching the interface it
	// just declined to touch.
	for _, a := range actions {
		if a.Changes() && a.Target != p.deferredPath() {
			t.Errorf("a refused pass still reports work: %s", a.Summary)
		}
	}
	if _, err := os.Stat(p.confPath); !os.IsNotExist(err) {
		t.Error("the planner wrote a config it had already decided not to apply")
	}
}

// A deferral must be visible to the health check, and must clear itself once the
// planner starts applying again.
//
// Before this, client-wg-owned probed the claim file and `ip link show` — both
// permanently true after a successful handover — so a frozen interface reported
// green. The worst case is a malformed credential: the planner keeps the
// last-good config forever, every later revocation silently fails to take effect,
// and the Web UI reports each one as successful.
func TestClientWGDeferralIsVisibleToTheHealthCheck(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	// The realistic way this happens: the operator narrows the pool below an
	// address that is already issued.
	bad := managedSpec(t)
	bad.Master.ClientWG.AddressPool = "10.81.0.0/24"

	applyPlan(t, p, bad)
	reason, err := os.ReadFile(p.deferredPath())
	if err != nil {
		t.Fatalf("the deferral was not recorded where the health check looks: %v", err)
	}
	if !strings.Contains(string(reason), "spec rejected") {
		t.Errorf("the recorded reason does not say what happened: %q", reason)
	}

	probe := health.ClientWGOwnedProbe(p.claimPath(), "wg0")
	if res := probe(context.Background()); res.OK {
		t.Error("the health check reports green while the planner is refusing the spec")
	}

	// Fixing the manifest clears it.
	applyPlan(t, p, spec)
	if _, err := os.Stat(p.deferredPath()); !os.IsNotExist(err) {
		t.Error("the deferral survived a pass that applied the spec")
	}
}

// An invalid spec must not abort the master's pass either — the last-good config
// keeps serving clients while the operator fixes the manifest.
func TestClientWGPlannerKeepsTheLastGoodConfigOnAnInvalidSpec(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	// The operator moved the pool in the manifest, leaving an issued address
	// outside it — the realistic way this spec goes invalid in production.
	spec.Master.ClientWG.AddressPool = "10.81.0.0/24"

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v, want a refusal that does not abort the pass", err)
	}
	if got := summaries(actions); !strings.Contains(got, "spec rejected") {
		t.Fatalf("plan does not explain the rejection:\n%s", got)
	}
	if _, err := os.Stat(p.confPath); !os.IsNotExist(err) {
		t.Error("the planner wrote a config it had rejected")
	}
}

// Choosing the userspace backend is not a way around the module gate. awg-quick
// only falls back to the daemon when the KERNEL add fails, so on a node with a
// 1.x module the kernel carries the interface regardless of the manifest — and
// rejects the 3.x config. Refuse rather than take the client leg down.
func TestClientWGPlannerRefusesUserspaceAWG3OnALegacyModule(t *testing.T) {
	p := clientPlanner(t, true)
	p.awgGen = func() (int, error) { return 1, nil }
	p.lookPath = func(string) (string, error) { return "/usr/bin/amneziawg-go", nil }
	spec := awg3Spec(t)
	spec.Master.ClientWG.Backend = domain.ClientWGBackendUserspace

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v, want a refusal", err)
	}
	if got := summaries(actions); !strings.Contains(got, "refused") {
		t.Fatalf("userspace backend skipped the module gate:\n%s", got)
	}
}

// …and it must refuse when the daemon it names is not installed at all, which is
// the state of every node in this fleet today.
func TestClientWGPlannerRefusesUserspaceWithoutTheDaemon(t *testing.T) {
	p := clientPlanner(t, true)
	p.awgGen = func() (int, error) { return 0, awgmod.ErrGenerationUnknown }
	p.lookPath = func(string) (string, error) { return "", errors.New("not found in $PATH") }
	spec := awg3Spec(t)
	spec.Master.ClientWG.Backend = domain.ClientWGBackendUserspace

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v, want a refusal", err)
	}
	got := summaries(actions)
	if !strings.Contains(got, "not installed") {
		t.Fatalf("plan does not name the missing daemon:\n%s", got)
	}
}

// On a node with no kernel module and a working daemon, userspace is exactly the
// right answer and must be allowed.
func TestClientWGPlannerAllowsUserspaceOnAModuleLessNode(t *testing.T) {
	p := clientPlanner(t, true)
	p.awgGen = func() (int, error) { return 0, awgmod.ErrGenerationUnknown }
	p.lookPath = func(string) (string, error) { return "/usr/bin/amneziawg-go", nil }
	spec := awg3Spec(t)
	spec.Master.ClientWG.Backend = domain.ClientWGBackendUserspace

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v", err)
	}
	if got := summaries(actions); strings.Contains(got, "refused") {
		t.Fatalf("userspace on a module-less node was refused:\n%s", got)
	}
}

// awg3Spec is a managed spec asking for AmneziaWG 3.x.
func awg3Spec(t *testing.T) domain.NodeSpec {
	t.Helper()
	spec := managedSpec(t)
	spec.Master.ClientWG.AWG.Shared.HeaderProtectionKey = "aGVhZGVyLXByb3RlY3Rpb24ta2V5LTAwMDAwMDAwMDA="
	return spec
}

// --- interface ownership -------------------------------------------------
//
// The handover ADOPTS wg-easy's private key so client configs keep working, so
// our public key and wg-easy's are the same value by design. Ownership therefore
// cannot be answered by identity, and these tests pin the two mechanisms that
// replace it: a claim file for "did we raise it", and a peer-set comparison for
// "does the live interface serve what the spec says".

// A wg-easy container that survived a reboot and recreated wg0 carries wg-easy's
// peer list. The config has not changed and the interface is up, so a naive pass
// reports converged while end users authenticate against the wrong peer set.
func TestClientWGPlannerReclaimsAnInterfaceServingOtherPeers(t *testing.T) {
	p := clientPlanner(t, true)
	p.ifacePeers = func(string) ([]string, error) { return []string{"c29tZWJvZHktZWxzZXMtcGVlci0wMDAwMDAwMDAw"}, nil }
	spec := managedSpec(t)
	applyPlan(t, p, spec)

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(actions)
	if strings.Contains(got, "already up") {
		t.Fatalf("planner accepted an interface serving somebody else's peers:\n%s", got)
	}
	if !strings.Contains(got, "live peers do not match") {
		t.Fatalf("planner did not explain the takeover:\n%s", got)
	}
}

// The steady state: the live peers ARE ours, so nothing happens.
func TestClientWGPlannerConvergedWhenPeersMatch(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	want := spec.Master.ClientWG.Clients[0].PublicKey
	p.ifacePeers = func(string) ([]string, error) { return []string{want}, nil }
	applyPlan(t, p, spec)

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "already up") {
		t.Fatalf("a converged interface reported work:\n%s", got)
	}
}

// Rollback: we raised the interface, so we release it — once. This is the case
// that used to tear down wg-easy's interface on every pass forever.
func TestClientWGPlannerReleasesItsClaimOnce(t *testing.T) {
	p := clientPlanner(t, true)
	applyPlan(t, p, managedSpec(t))
	claimIt(t, p) // a previous pass raised it successfully
	unmanaged := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}

	first, err := p.Plan(context.Background(), unmanaged)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(first); !strings.Contains(got, "bring ours down") {
		t.Fatalf("planner did not release its own interface:\n%s", got)
	}
	// Apply the release, then look again: wg-easy now owns wg0 and we must not
	// touch it a second time.
	applyPlan(t, p, unmanaged)
	second, err := p.Plan(context.Background(), unmanaged)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(second)
	if strings.Contains(got, "down") {
		t.Fatalf("planner tore down wg-easy's interface after releasing its own:\n%s", got)
	}
	for _, a := range second {
		if a.Changes() {
			t.Fatalf("a released interface still reports drift: %s", a.Summary)
		}
	}
}

// A master that never had the knob on must stay entirely out of it, even though
// its agent holds wg-easy's adopted key and an interface named wg0 is up.
func TestClientWGPlannerNeverTouchesAnUnclaimedInterface(t *testing.T) {
	p := clientPlanner(t, true)
	actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(actions)
	if strings.Contains(got, "down") {
		t.Fatalf("planner tore down an interface it never raised:\n%s", got)
	}
	for _, a := range actions {
		if a.Changes() {
			t.Fatalf("an unmanaged master reports drift every pass: %s", a.Summary)
		}
	}
}

// A failed bring-up must not abort the master's pass: this planner runs before
// mihomo, the NAT rules and the resolver, and a client leg that will not come up
// is not a reason to freeze all of them.
func TestClientWGPlannerBringUpIsBestEffort(t *testing.T) {
	p := clientPlanner(t, false)
	actions, err := p.Plan(context.Background(), managedSpec(t))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	var sawUp bool
	for _, a := range actions {
		if strings.Contains(a.Summary, "bring the client interface up") {
			sawUp = true
		}
	}
	if !sawUp {
		t.Fatal("no bring-up action was planned")
	}
	// Run the whole plan through the engine: awg-quick does not exist here, so the
	// bring-up fails. A hard action would abort and the report would carry the
	// error; a best-effort one lets the pass finish, which is the property that
	// keeps mihomo, the NAT rules and the resolver converging.
	eng := reconcile.NewEngine(nil, p)
	if _, err := eng.Reconcile(context.Background(), managedSpec(t), reconcile.ModeApply); err != nil {
		t.Fatalf("a failing bring-up aborted the master's pass: %v", err)
	}
}

// The wg-easy container is retired only once we are carrying the leg, and only
// while it is still there — otherwise every pass forever reports drift.
// wg-easy is retired a whole pass AFTER the interface is observed up — never in
// the pass that raised it.
//
// Every awg-quick step is best-effort so a client interface that will not come up
// cannot freeze mihomo, the NAT, DOCKER-USER, blocky and the VLESS inbound with
// it. That made "retire after the bring-up" mean "retire after the ATTEMPT": a
// failed `up` deleted the only thing still serving clients and reported a warning.
// wg-easy is retired only once there is PROOF the agent raised the interface —
// and the proof is a claim written by a bring-up that actually succeeded.
//
// The claim used to be appended to the plan unconditionally, so a failed
// awg-quick up still produced one. Two decisions then read it as evidence the
// agent carries the interface: retiring the fallback, and the client-wg-owned
// health check. Neither fact followed from it.
func TestClientWGPlannerRetiresWGEasyOnlyWithProofItRaisedTheInterface(t *testing.T) {
	p := clientPlanner(t, false) // interface not up yet
	p.containerPresent = func(string) bool { return true }
	spec := managedSpec(t)

	// Pass 1 raises it. The fallback must still be standing when the pass ends,
	// and — because awg-quick cannot succeed here — no claim may be recorded.
	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "bring the client interface up") {
		t.Fatalf("first pass did not raise the interface:\n%s", got)
	}
	if got := summaries(actions); strings.Contains(got, "retire") {
		t.Fatalf("wg-easy retired in the same pass that raised our interface:\n%s", got)
	}
	applyPlan(t, p, spec)
	if _, err := os.Stat(p.claimPath()); err == nil {
		t.Fatal("a claim was recorded although the bring-up failed")
	}

	// Now the bring-up succeeds: the interface is up, serving our peers, and the
	// claim is on disk.
	p.up = func(string) bool { return true }
	p.ifacePeers = func(string) ([]string, error) {
		return []string{spec.Master.ClientWG.Clients[0].PublicKey}, nil
	}
	claimIt(t, p)
	actions, err = p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "retire the wg-easy container") {
		t.Fatalf("wg-easy is never retired once we demonstrably carry the interface:\n%s", got)
	}

	// Never for a container that is already gone.
	p.containerPresent = func(string) bool { return false }
	actions, err = p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); strings.Contains(got, "retire") {
		t.Fatalf("planner tries to retire a container that is already gone:\n%s", got)
	}
}

// The peer probe fails OPEN so a broken `awg show` cannot bounce a healthy
// interface. That trade is right for deciding whether to re-apply and wrong for
// deciding whether to delete the only fallback, so retirement additionally
// requires that the probe actually answered.
func TestClientWGPlannerKeepsWGEasyWhenThePeerProbeCannotAnswer(t *testing.T) {
	p := clientPlanner(t, true)
	p.containerPresent = func(string) bool { return true }
	p.ifacePeers = func(string) ([]string, error) { return nil, errors.New("awg: command not found") }
	spec := managedSpec(t)
	applyPlan(t, p, spec)
	claimIt(t, p)

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); strings.Contains(got, "retire") {
		t.Fatalf("the fallback was deleted on the strength of a probe that could not run:\n%s", got)
	}
}

// The failure this ordering exists to prevent: awg-quick is missing, so the
// bring-up cannot work. wg-easy must still be there afterwards.
func TestClientWGPlannerKeepsWGEasyWhenTheInterfaceNeverComesUp(t *testing.T) {
	p := clientPlanner(t, false)
	p.containerPresent = func(string) bool { return true }
	spec := managedSpec(t)

	for pass := 1; pass <= 3; pass++ {
		actions, err := p.Plan(context.Background(), spec)
		if err != nil {
			t.Fatalf("pass %d: Plan() error = %v", pass, err)
		}
		if got := summaries(actions); strings.Contains(got, "retire") {
			t.Fatalf("pass %d retired the fallback while our interface is still down:\n%s", pass, got)
		}
		applyPlan(t, p, spec) // the exec actions no-op here, exactly as a failed up does
	}
}

// --- handover mechanics --------------------------------------------------

// Planner ORDER is part of the contract, not an implementation detail: the
// client interface must be released before compose restores wg-easy, or the
// rollback pass tears down the interface wg-easy just created.
func TestClientInterfacePlannerRunsBeforeCompose(t *testing.T) {
	var client, compose int = -1, -1
	for i, pl := range Planners(Input{Paths: PathsUnder(t.TempDir())}) {
		switch pl.(type) {
		case clientWGPlanner:
			client = i
		case composePlanner:
			compose = i
		}
	}
	if client < 0 || compose < 0 {
		t.Fatalf("planners not found: client=%d compose=%d", client, compose)
	}
	if client > compose {
		t.Fatalf("client interface planner runs at %d, after compose at %d — rollback would tear down wg-easy's interface", client, compose)
	}
}

// Revoking or pausing the LAST credential must actually take effect.
//
// This used to be the opposite test. The planner refused any spec with zero
// clients while peers were live, reading that shape as "the controller could not
// read its credential store" — and it is also exactly the shape of the operator
// legitimately revoking everyone. Revoke reported success in the UI, the planner
// declined every pass forever, and the revoked peer stayed on the live interface.
// A revocation that does not revoke is a security hole, and the old test locked it
// in.
//
// The floor is gone rather than narrowed, for three reasons. The controller cannot
// produce that spec: a store failure fails the whole render (11e785b, and its own
// test). No RELEASED controller ever could — keybroker/client_wg.go does not exist
// in any tag, so the only builds with the old behaviour are dev commits from a
// 20-hour window that was never shipped. And the floor only ever fired at EXACTLY
// zero, so a controller bug rendering one client instead of nine sailed straight
// through it: it was never the defence it read as. The controller is the authority
// on who its clients are, and the agent's job is to converge on that.
func TestClientWGPlannerAppliesARevokeOfTheLastCredential(t *testing.T) {
	p := clientPlanner(t, true)
	full := managedSpec(t)
	live := full.Master.ClientWG.Clients[0].PublicKey
	p.ifacePeers = func(string) ([]string, error) { return []string{live}, nil }
	applyPlan(t, p, full)

	empty := managedSpec(t)
	empty.Master.ClientWG.Clients = nil

	actions, err := p.Plan(context.Background(), empty)
	if err != nil {
		t.Fatalf("Plan() = %v", err)
	}
	got := summaries(actions)
	if strings.Contains(got, "refusing a spec with no clients") {
		t.Fatalf("the planner still refuses a legitimate revoke-all:\n%s", got)
	}
	if !strings.Contains(got, "bring the client interface up") {
		t.Fatalf("the revoke never reaches the live interface:\n%s", got)
	}

	// Absence of the whole block still means "release it" — a different instruction
	// from "serve nobody", and the one the operator uses to hand the leg back.
	unmanaged := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	claimIt(t, p)
	if got := summaries(mustPlan(t, p, unmanaged)); !strings.Contains(got, "bring ours down") {
		t.Fatalf("releasing the interface no longer works:\n%s", got)
	}

	// And a master with no credentials yet still renders an empty interface, which
	// is how a freshly managed master starts.
	p2 := clientPlanner(t, false)
	p2.ifacePeers = func(string) ([]string, error) { return nil, nil }
	if got := summaries(mustPlan(t, p2, empty)); strings.Contains(got, "refusing a spec") {
		t.Fatalf("a master with no clients yet was refused:\n%s", got)
	}
}

func mustPlan(t *testing.T, p clientWGPlanner, spec domain.NodeSpec) []reconcile.Action {
	t.Helper()
	a, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	return a
}

// The prober must be on the live interface AND in the peer-match check.
//
// Those are two halves of one requirement. The agent adds this peer locally, so
// the controller's spec does not describe it — and servesDesiredPeers compares the
// LIVE interface against a spec. Comparing against the un-augmented one would see
// an extra peer it cannot explain, decide the interface has drifted, and re-apply
// the config on every single pass: a client interface rewritten once a minute
// because it is carrying the thing that measures it.
func TestClientInterfaceCarriesTheProberAndDoesNotCallItDrift(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "wg0.conf")
	spec := managedSpec(t)
	clientPub := spec.Master.ClientWG.Clients[0].PublicKey

	p := clientWGPlanner{
		confPath: conf, privateKey: "serverkey", synthKey: wg.KeyPair{PrivateKey: "synthpriv", PublicKey: "SYNTHPUB"},
		up:               func(string) bool { return true },
		ifacePeers:       func(string) ([]string, error) { return []string{clientPub, "SYNTHPUB"}, nil },
		containerPresent: func(string) bool { return false },
		lookPath:         func(string) (string, error) { return "", errors.New("absent") },
	}
	// applyPlan, not applyNonExec: the interface config is rendered with a redactor,
	// so its Display is the REDACTED text. Writing that back would leave a file that
	// never matches the render and an interface that is "changed" on every pass.
	applyPlan(t, p, spec)
	rendered, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	if !strings.Contains(string(rendered), "SYNTHPUB") {
		t.Errorf("the prober is not on the interface:\n%s", rendered)
	}

	// Second pass over the same converged state must not re-apply.
	acts, perr := p.Plan(context.Background(), spec)
	if perr != nil {
		t.Fatalf("second Plan: %v", perr)
	}
	for _, a := range acts {
		if a.Kind == reconcile.ActionExec && strings.Contains(a.Summary, "config changed") {
			t.Errorf("the interface was re-applied although nothing changed: %q", a.Summary)
		}
	}
}

// Adding a peer must not cost every established session on the interface.
//
// `awg-quick down` + `up` destroys the device, and the upgrade that introduces
// the client-path prober adds exactly one peer: without this, every client on the
// live master re-handshakes so the master can measure itself. The same applies to
// an operator issuing a new credential.
func TestAddingAPeerDoesNotRecreateTheInterface(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	applyPlan(t, p, spec)
	claimIt(t, p)

	// The interface is up and serves exactly today's peers. The next pass adds one.
	existing := spec.Master.ClientWG.Clients[0].PublicKey
	p.ifacePeers = func(string) ([]string, error) { return []string{existing}, nil }

	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	grown := spec
	cw := *spec.Master.ClientWG
	ms := *spec.Master
	ms.ClientWG = &cw
	grown.Master = &ms
	cw.Clients = append(append([]domain.WGClientPeer(nil), cw.Clients...), domain.WGClientPeer{
		Name: "phone", PublicKey: kp.PublicKey, Address: "10.80.0.9/32",
	})

	got := summaries(mustPlan(t, p, grown))
	if strings.Contains(got, "bring the client interface down") {
		t.Fatalf("adding one peer took the whole interface down:\n%s", got)
	}
	if !strings.Contains(got, "add peer phone") {
		t.Fatalf("the new peer never reaches the live interface:\n%s", got)
	}
}

// A live interface carrying somebody else's peer is not an interface missing an
// entry — its INTERFACE parameters are somebody else's too, and `awg set` cannot
// correct those. That case must still recreate the device.
func TestAForeignPeerListStillRecreatesTheInterface(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	applyPlan(t, p, spec)
	claimIt(t, p)
	p.ifacePeers = func(string) ([]string, error) {
		return []string{"c29tZWJvZHktZWxzZXMtcGVlci0wMDAwMDAwMDAw"}, nil
	}
	got := summaries(mustPlan(t, p, spec))
	if !strings.Contains(got, "bring the client interface up") {
		t.Fatalf("a foreign peer list was patched instead of rebuilt:\n%s", got)
	}
}

// An interface-level change — the listen port, the MTU, the AmneziaWG parameters —
// is fixed when the device is created and cannot be applied with `awg set`.
func TestAnInterfaceChangeStillRecreatesTheInterface(t *testing.T) {
	p := clientPlanner(t, true)
	spec := managedSpec(t)
	applyPlan(t, p, spec)
	claimIt(t, p)
	existing := spec.Master.ClientWG.Clients[0].PublicKey
	p.ifacePeers = func(string) ([]string, error) { return []string{existing}, nil }

	moved := spec
	cw := *spec.Master.ClientWG
	ms := *spec.Master
	ms.ClientWG = &cw
	moved.Master = &ms
	cw.MTU = 1280
	got := summaries(mustPlan(t, p, moved))
	if !strings.Contains(got, "bring the client interface up") {
		t.Fatalf("an MTU change was applied as a peer edit:\n%s", got)
	}
}
