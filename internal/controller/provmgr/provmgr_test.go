package provmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

// writeFakeAgentBin writes a stand-in agent binary and returns its path. Apply-mode
// provisioning refuses without one (a node would get a unit with nothing to run),
// so every fixture that provisions for real needs a file here.
func writeFakeAgentBin(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wgfleet-agent")
	if err := os.WriteFile(p, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
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
	m := New(st, ca, testFleet(), Options{ControllerEndpoint: "ctl:8443", Dial: dial, AgentBinPath: writeFakeAgentBin(t)}, log)
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

func TestProvisionClearsDecommissionAndDrain(t *testing.T) {
	mock := readyMock()
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	ctx := context.Background()

	// First provision creates the inventory row.
	if _, err := m.Provision(ctx, "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Operator decommissions (and drains) the node.
	if err := st.SetNodeDecommission(ctx, "exit-de-1", true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeDrain(ctx, "exit-de-1", true); err != nil {
		t.Fatal(err)
	}
	// Re-provisioning must CLEAR both, or the keybroker keeps rendering
	// Decommission=true and the agent tears down on every reconcile (never comes back).
	if _, err := m.Provision(ctx, "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	node, err := st.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if node.Decommission {
		t.Error("Decommission must be cleared on re-provision (else the agent tears down forever)")
	}
	if node.Drain {
		t.Error("Drain must be cleared on re-provision")
	}
}

// An exit that changes address: the operator edits public_ip in the manifest and
// re-provisions. The store row must follow, or the console and the support bundle
// keep reporting the address the node had on the day it was onboarded — nothing
// else ever writes this field (the agent advertises no public IP).
func TestReprovisionRefreshesManifestInventory(t *testing.T) {
	mock := readyMock()
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	ctx := context.Background()

	if _, err := m.Provision(ctx, "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// The node moved: new public address, declared in the manifest. A manifest edit
	// takes effect on controller restart, so the second run is a fresh manager over
	// the same store — exactly what the operator gets.
	fleet := testFleet()
	fleet.Exits[0].PublicIP = "198.51.100.99"
	fleet.Exits[0].MgmtAddr = "10.20.0.9"
	fleet.Exits[0].Region = "nl"
	fleet.Exits[0].SSH.Host = "198.51.100.99"
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	m = New(st, ca, fleet, Options{
		ControllerEndpoint: "ctl:8443",
		Dial:               func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil },
		AgentBinPath:       writeFakeAgentBin(t),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := m.Provision(ctx, "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	node, gerr := st.GetNode(ctx, "exit-de-1")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if node.PublicIP != "198.51.100.99" {
		t.Errorf("PublicIP = %q, want the manifest's new 198.51.100.99", node.PublicIP)
	}
	if node.MgmtAddr != "10.20.0.9" {
		t.Errorf("MgmtAddr = %q, want the manifest's new 10.20.0.9", node.MgmtAddr)
	}
	if node.Region != "nl" {
		t.Errorf("Region = %q, want the manifest's new nl", node.Region)
	}
	if node.SSH.Host != "198.51.100.99" {
		t.Errorf("SSH.Host = %q, want the manifest's new 198.51.100.99", node.SSH.Host)
	}
}

// The other half of the refresh rule: a manifest SILENT about a field must not
// blank what the store already has. Only non-empty manifest values overwrite.
func TestReprovisionKeepsFieldsTheManifestOmits(t *testing.T) {
	mock := readyMock()
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	ctx := context.Background()

	if _, err := m.Provision(ctx, "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("provision: %v", err)
	}
	fleet := testFleet()
	fleet.Exits[0].Region = "" // manifest says nothing about the region any more
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	m = New(st, ca, fleet, Options{
		ControllerEndpoint: "ctl:8443",
		Dial:               func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil },
		AgentBinPath:       writeFakeAgentBin(t),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := m.Provision(ctx, "exit-de-1", provisioner.ModeApply); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	node, gerr := st.GetNode(ctx, "exit-de-1")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if node.Region != "de" {
		t.Errorf("Region = %q, want the stored de kept (manifest is silent)", node.Region)
	}
}

// A master's public address is public_ip and nothing else: ssh.host is often the
// management overlay, and laundering it through the store would put an overlay
// address in the console's PUBLIC field and in every client profile the keybroker
// falls back to it for.
func TestMasterManifestNodeDoesNotBorrowSSHHost(t *testing.T) {
	mock := readyMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	m.fleet.Masters = []config.MasterConfig{{
		Name: "master-xa-1", MgmtAddr: "10.20.25.254",
		SSH: config.SSHConfig{Host: "10.20.25.254", User: "root"}, // overlay address
	}}
	m.fleet.Exits[0].SSH.Host = "198.51.100.7"

	nodes := m.ManifestNodes()
	if len(nodes) != 2 {
		t.Fatalf("ManifestNodes() = %d nodes, want the master and the exit", len(nodes))
	}
	for _, n := range nodes {
		switch n.Role {
		case domain.RoleMaster:
			if n.PublicIP != "" {
				t.Errorf("master PublicIP = %q, want empty (public_ip unset; ssh.host must not stand in)", n.PublicIP)
			}
		case domain.RoleExit:
			// An exit's endpoint is dialled by the MASTER, so ssh.host is a sane default.
			if n.PublicIP != "198.51.100.7" {
				t.Errorf("exit PublicIP = %q, want the ssh.host default", n.PublicIP)
			}
		}
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
		AgentBinPath:       writeFakeAgentBin(t),
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
	// The upgrade digest-verifies the upload before it will restart the agent, so
	// the mock must answer sha256sum with the digest of the bytes it received.
	sum := sha256.Sum256([]byte("\x7fELF-fake-binary"))
	mock.PrefixResponses["sha256sum"] = hex.EncodeToString(sum[:]) + "  /usr/local/bin/wgfleet-agent"
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

func TestRecordUpgradeOutcome(t *testing.T) {
	m, st := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return provisioner.NewMockRunner(), nil })
	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}

	// A failed background upgrade is recorded on LastError, state preserved.
	m.recordUpgradeOutcome(ctx, "exit-de-1", io.ErrUnexpectedEOF)
	n, _ := st.GetNode(ctx, "exit-de-1")
	if n.LastError != "agent upgrade failed: unexpected EOF" {
		t.Fatalf("expected upgrade failure recorded, got %q", n.LastError)
	}
	if n.State != domain.StateReady {
		t.Fatalf("state must be preserved, got %q", n.State)
	}

	// A subsequent success clears the recorded error.
	m.recordUpgradeOutcome(ctx, "exit-de-1", nil)
	n, _ = st.GetNode(ctx, "exit-de-1")
	if n.LastError != "" {
		t.Fatalf("success should clear LastError, got %q", n.LastError)
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

// --upgrade-agent is the third path that upgrades an agent, alongside the rollout
// coordinator and the wire-version gate. It was the only one that took no per-node
// lock, so it could drive a second concurrent SSH upload+restart against a node a
// rolling upgrade was already mid-way through.
func TestUpgradeAgentTakesThePerNodeLock(t *testing.T) {
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return readyMock(), nil })
	if err := m.acquire("exit-1"); err != nil {
		t.Fatal(err)
	}
	defer m.clearInflight("exit-1")

	_, err := m.UpgradeAgent(context.Background(), "exit-1", provisioner.ModeApply)
	if err == nil {
		t.Fatal("an upgrade must be refused while that node is already in flight")
	}
}

// A dry run executes nothing, so it must not be blocked behind a running upgrade.
func TestUpgradeAgentPlanIsNotBlockedByInflight(t *testing.T) {
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return readyMock(), nil })
	if err := m.acquire("exit-1"); err != nil {
		t.Fatal(err)
	}
	defer m.clearInflight("exit-1")

	// It may still fail for unrelated reasons (no ssh target / no binary in the test
	// fixture); what matters is that it is not refused BY THE LOCK.
	_, err := m.UpgradeAgent(context.Background(), "exit-1", provisioner.ModePlan)
	if err != nil && strings.Contains(err.Error(), "in flight") {
		t.Fatalf("plan mode must not contend on the per-node lock: %v", err)
	}
}
