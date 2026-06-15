package provmgr

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func testFleet() config.FleetSection {
	return config.FleetSection{
		Exits: []config.ExitConfig{{
			Name: "exit-de-1", Region: "de", AddressPool: "10.81.0.0/24",
			SSH: config.SSHConfig{Host: "198.51.100.7", User: "root", KeyPath: "/tmp/key"},
		}},
	}
}

// readyMock is a MockRunner whose facts pass preflight (Linux + AWG module).
func readyMock() *provisioner.MockRunner {
	r := provisioner.NewMockRunner()
	r.Responses["uname -s"] = "Linux"
	r.Responses["uname -m"] = "x86_64"
	r.Responses["uname -r"] = "6.8.0"
	r.PrefixResponses["command -v "] = "yes"
	r.PrefixResponses["k=$(uname -r)"] = "AWGKMOD=yes (loaded, test)"
	return r
}

func newManager(t *testing.T, dial DialFunc) (*Manager, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(st, ca, testFleet(), Options{ControllerEndpoint: "ctl:8443", Dial: dial}, log)
	return m, st
}

func TestProvisionApplyViaMock(t *testing.T) {
	mock := readyMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })

	rep, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(rep.Plan.Steps) == 0 {
		t.Error("expected bootstrap steps")
	}
	// The node identity bundle must have been uploaded.
	if _, ok := mock.Uploaded["/etc/wgfleet/node.crt"]; !ok {
		t.Error("node cert not uploaded")
	}
}

func TestProvisionPersistsInventory(t *testing.T) {
	mock := readyMock()
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })

	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// The manifest inventory must land in the store so the keybroker can render
	// the master↔exit endpoint. With no explicit public_ip, it falls back to the
	// SSH host (the typical "you SSH to the node at its public IP" case).
	node, err := st.GetNode(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatalf("node not persisted: %v", err)
	}
	if node.PublicIP != "198.51.100.7" {
		t.Errorf("PublicIP = %q, want 198.51.100.7 (ssh.host fallback)", node.PublicIP)
	}
}

func TestProvisionPlanModeDoesNotPersist(t *testing.T) {
	mock := readyMock()
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })

	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModePlan); err != nil {
		t.Fatalf("provision plan: %v", err)
	}
	if _, err := st.GetNode(context.Background(), "exit-de-1"); err == nil {
		t.Error("plan mode must not persist the node to the store")
	}
}

func TestPublicIPExplicitOverridesSSHHost(t *testing.T) {
	if got := publicIP("203.0.113.9", "10.0.0.1"); got != "203.0.113.9" {
		t.Errorf("explicit public_ip = %q, want 203.0.113.9", got)
	}
	if got := publicIP("", "10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("fallback = %q, want ssh host 10.0.0.1", got)
	}
}

func TestProvisionNilStoreDoesNotPanic(t *testing.T) {
	// A Manager built without a store (defensive: callers should pass one, but a
	// nil store must degrade gracefully, not panic — regression for the SIGSEGV in
	// ensureNode when sync Provision started persisting inventory).
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mock := readyMock()
	m := New(nil, ca, testFleet(), Options{
		ControllerEndpoint: "ctl:8443",
		Dial:               func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil },
	}, log)

	if _, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision with nil store must not panic or error: %v", err)
	}
}

func TestProvisionableGating(t *testing.T) {
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return readyMock(), nil })
	if !m.Provisionable("exit-de-1") {
		t.Error("exit-de-1 should be provisionable")
	}
	if m.Provisionable("ghost") {
		t.Error("unknown node should not be provisionable")
	}
}

func TestTriggerAsyncTransitionsState(t *testing.T) {
	mock := readyMock()
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })

	if err := m.TriggerAsync("exit-de-1"); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	// Node should exist and end up Reconciling once the async job finishes.
	waitState(t, st, "exit-de-1", domain.StateReconciling)
}

func TestTriggerAsyncErrorOnSSHFailure(t *testing.T) {
	dialErr := func(domain.SSHTarget) (provisioner.Runner, error) {
		return nil, context.DeadlineExceeded
	}
	m, st := newManager(t, dialErr)
	if err := m.TriggerAsync("exit-de-1"); err != nil {
		t.Fatalf("trigger should start: %v", err)
	}
	waitState(t, st, "exit-de-1", domain.StateError)
	n, _ := st.GetNode(context.Background(), "exit-de-1")
	if n.LastError == "" {
		t.Error("failed provisioning should record an error")
	}
}

func TestTriggerAsyncRejectsUnprovisionable(t *testing.T) {
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return readyMock(), nil })
	if err := m.TriggerAsync("ghost"); err == nil {
		t.Error("unknown node should be rejected")
	}
}

func TestUpgradeAgentUploadsBinaryAndRestarts(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "wgfleet-agent")
	if err := os.WriteFile(bin, []byte("\x7fELF-fake-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	mock := provisioner.NewMockRunner()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	m.opts.AgentBinPath = bin

	rep, err := m.UpgradeAgent(context.Background(), "exit-de-1", provisioner.ModeApply)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if len(rep.Plan.Steps) == 0 {
		t.Fatal("expected upgrade steps")
	}
	if got := mock.Uploaded["/usr/local/bin/wgfleet-agent"]; string(got) != "\x7fELF-fake-binary" {
		t.Errorf("agent binary not uploaded, got %q", got)
	}
	if !mock.RanCommand("systemctl restart wgfleet-agent") {
		t.Error("agent was not restarted")
	}
	// The upgrade must be lightweight: no full bootstrap (no hardening/deps).
	if mock.RanCommand("sshd") || mock.RanCommand("get.docker.com") {
		t.Error("upgrade should not re-run full bootstrap steps")
	}
}

func TestUpgradeAgentRequiresBinary(t *testing.T) {
	mock := provisioner.NewMockRunner()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	// No AgentBinPath configured.
	if _, err := m.UpgradeAgent(context.Background(), "exit-de-1", provisioner.ModeApply); err == nil {
		t.Error("upgrade without a configured binary should error")
	}
}

func TestUpgradeAgentPlanModeChangesNothing(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "wgfleet-agent")
	_ = os.WriteFile(bin, []byte("bin"), 0o755)
	mock := provisioner.NewMockRunner()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	m.opts.AgentBinPath = bin

	if _, err := m.UpgradeAgent(context.Background(), "exit-de-1", provisioner.ModePlan); err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(mock.Ran) != 0 || len(mock.Uploaded) != 0 {
		t.Errorf("plan mode must not touch the node: ran=%v uploaded=%v", mock.Ran, mock.Uploaded)
	}
}

func waitState(t *testing.T, st store.Store, id string, want domain.NodeState) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if n, err := st.GetNode(context.Background(), id); err == nil && n.State == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	n, _ := st.GetNode(context.Background(), id)
	t.Fatalf("node %q state = %q, want %q", id, n.State, want)
}
