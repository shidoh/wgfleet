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
		confPath:   filepath.Join(t.TempDir(), "wg0.conf"),
		privateKey: kp.PrivateKey,
		up:         func(string) bool { return up },
		awgGen:     func() (int, error) { return 3, nil },
		ifaceKey:   func(string) (string, error) { return wg.PublicKeyOf(kp.PrivateKey) },
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
	if !strings.Contains(got, "up with the new config") {
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
	if strings.Contains(got, "up with the new config") {
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
	if got := summaries(second); !strings.Contains(got, "was down") {
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
// "Is wg0 up" and "is wg0 OURS" are different questions, and the whole handover
// turns on the second. wg-easy creates an interface by the same name, so a
// planner that only checks existence will hand the client leg back to it and
// report a converged pass.

// notOurs is a live interface carrying somebody else's key — what wg-easy's own
// wg0 looks like to us.
const notOurs = "b3RoZXItaW50ZXJmYWNlLWtleS0wMDAwMDAwMDAwMA="

// TestClientWGPlannerReclaimsAForeignInterface: wg-easy came back after a reboot
// and holds wg0. The config has not changed, so a naive planner sees "up" and
// does nothing — leaving end users authenticating against wg-easy's peer list
// while every dashboard reads healthy. We must take it and raise our own.
func TestClientWGPlannerReclaimsAForeignInterface(t *testing.T) {
	p := clientPlanner(t, true)
	p.ifaceKey = func(string) (string, error) { return notOurs, nil }
	spec := managedSpec(t)
	applyPlan(t, p, spec)

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(actions)
	if strings.Contains(got, "already up") {
		t.Fatalf("planner accepted an interface it does not own:\n%s", got)
	}
	if !strings.Contains(got, "up") {
		t.Fatalf("planner did not reclaim the interface:\n%s", got)
	}
}

// TestClientWGPlannerLeavesAForeignInterfaceAlone is the rollback case, and the
// one that used to break: the operator clears the knob, wg-easy is restored and
// creates wg0 — and we must NOT tear it down. Doing so leaves the client leg
// down on every pass forever, because our config file deliberately stays on disk.
func TestClientWGPlannerLeavesAForeignInterfaceAlone(t *testing.T) {
	p := clientPlanner(t, true)
	p.ifaceKey = func(string) (string, error) { return notOurs, nil }

	actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(actions)
	if strings.Contains(got, "down") {
		t.Fatalf("planner tore down an interface belonging to wg-easy:\n%s", got)
	}
	for _, a := range actions {
		if a.Changes() {
			t.Fatalf("unmanaged pass reports drift on somebody else's interface: %s", a.Summary)
		}
	}
}

// The unmanaged branch must still clean up OUR interface — that is what makes
// the handover reversible.
func TestClientWGPlannerLowersItsOwnInterfaceWhenHandedBack(t *testing.T) {
	p := clientPlanner(t, true)
	ours, err := wg.PublicKeyOf(p.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	p.ifaceKey = func(string) (string, error) { return ours, nil }

	actions, perr := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	if perr != nil {
		t.Fatalf("Plan() error = %v", perr)
	}
	if got := summaries(actions); !strings.Contains(got, "down") {
		t.Fatalf("planner left its own interface up after the handover was reversed:\n%s", got)
	}
}

// An unreadable interface (no awg tools, no interface) must not be assumed ours:
// tearing down on a failed probe is the destructive direction.
func TestClientWGPlannerDoesNotGuessOwnership(t *testing.T) {
	p := clientPlanner(t, true)
	p.ifaceKey = func(string) (string, error) { return "", errors.New("awg: no such interface") }

	actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); strings.Contains(got, "down") {
		t.Fatalf("planner tore down an interface it could not identify:\n%s", got)
	}
}

// --- handover mechanics --------------------------------------------------

// The compose planner must actively retire the wg-easy container once the agent
// owns the client leg. Dropping the service from the YAML is not enough: compose
// treats it as an orphan and leaves it running, `restart: unless-stopped` brings
// it back after a reboot, and it then holds wg0 and UDP 443 against us.
func TestComposePlannerRetiresWGEasyOnHandover(t *testing.T) {
	dir := t.TempDir()
	p := composePlanner{path: filepath.Join(dir, "docker-compose.yml"), up: func(string) bool { return true }}

	spec := managedSpec(t)
	spec.Master.Compose = domain.ComposeSpec{}
	spec.Master.ExternalController = "10.20.0.1:9090"
	spec.WGServer = domain.WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"}

	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	got := summaries(actions)
	if !strings.Contains(got, "retire the wg-easy container") {
		t.Fatalf("handed-over master does not retire wg-easy:\n%s", got)
	}
}

// While wg-easy still owns the leg, nothing may touch its container.
func TestComposePlannerLeavesWGEasyAloneWhenUnmanaged(t *testing.T) {
	dir := t.TempDir()
	p := composePlanner{path: filepath.Join(dir, "docker-compose.yml"), up: func(string) bool { return true }}

	spec := domain.NodeSpec{
		Role:     domain.RoleMaster,
		WGServer: domain.WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"},
		Master:   &domain.MasterSpec{ExternalController: "10.20.0.1:9090"},
	}
	actions, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); strings.Contains(got, "retire") {
		t.Fatalf("unmanaged master retires wg-easy:\n%s", got)
	}
}

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
