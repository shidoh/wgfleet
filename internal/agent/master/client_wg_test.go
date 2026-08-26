package master

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

// Turning the knob back off must take OUR interface down: leaving it up would
// fight wg-easy for the same UDP port.
func TestClientWGPlannerLowersTheInterfaceWhenHandedBack(t *testing.T) {
	p := clientPlanner(t, true)
	actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if got := summaries(actions); !strings.Contains(got, "bring it down") {
		t.Fatalf("plan did not lower the interface:\n%s", got)
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
func TestClientWGPlannerRefusesAWG3OnALegacyModule(t *testing.T) {
	p := clientPlanner(t, true)
	p.awgGen = func() (int, error) { return 1, nil }
	spec := managedSpec(t)
	spec.Master.ClientWG.AWG.Shared.HeaderProtectionKey = "aGVhZGVyLXByb3RlY3Rpb24ta2V5LTAwMDAwMDAwMDA="

	if _, err := p.Plan(context.Background(), spec); err == nil {
		t.Fatal("Plan() = nil error, want a refusal on a 1.x module")
	}
	if _, err := os.Stat(p.confPath); !os.IsNotExist(err) {
		t.Error("the planner wrote a config it had already decided not to apply")
	}
}

// The userspace backend carries its own 3.x support, so the module generation
// must not gate it.
func TestClientWGPlannerAllowsAWG3OnUserspaceBackend(t *testing.T) {
	p := clientPlanner(t, true)
	p.awgGen = func() (int, error) { return 1, nil }
	spec := managedSpec(t)
	spec.Master.ClientWG.Backend = domain.ClientWGBackendUserspace
	spec.Master.ClientWG.AWG.Shared.HeaderProtectionKey = "aGVhZGVyLXByb3RlY3Rpb24ta2V5LTAwMDAwMDAwMDA="

	if _, err := p.Plan(context.Background(), spec); err != nil {
		t.Fatalf("Plan() on the userspace backend = %v, want no module gate", err)
	}
}
