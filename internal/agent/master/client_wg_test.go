package master

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	for _, a := range actions {
		if a.Changes() {
			t.Errorf("a refused pass still reports work: %s", a.Summary)
		}
	}
	if _, err := os.Stat(p.confPath); !os.IsNotExist(err) {
		t.Error("the planner wrote a config it had already decided not to apply")
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
	applyPlan(t, p, managedSpec(t)) // claims the interface
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
func TestClientWGPlannerRetiresWGEasyOnlyWhenPresent(t *testing.T) {
	p := clientPlanner(t, false)
	p.containerPresent = func(string) bool { return true }
	actions, err := p.Plan(context.Background(), managedSpec(t))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "retire the wg-easy container") {
		t.Fatalf("wg-easy is never retired:\n%s", got)
	}

	p.containerPresent = func(string) bool { return false }
	actions, err = p.Plan(context.Background(), managedSpec(t))
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); strings.Contains(got, "retire") {
		t.Fatalf("planner tries to retire a container that is already gone:\n%s", got)
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
