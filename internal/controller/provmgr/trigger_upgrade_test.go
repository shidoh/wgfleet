package provmgr

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// upgradeManager builds a Manager with a real agent binary on disk and a dialer
// the test controls, so TriggerUpgrade's async path can be driven end to end.
func upgradeManager(t *testing.T, dial DialFunc) (*Manager, store.Store) {
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
	bin := filepath.Join(t.TempDir(), "wgfleet-agent")
	if err := os.WriteFile(bin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New(st, ca, testFleet(), Options{
		ControllerEndpoint: "ctl:8443", Dial: dial, AgentBinPath: bin,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetBaseContext(context.Background())
	return m, st
}

// TestTriggerUpgradeRejectsSecondJobOnSameNode is the guard that matters: this
// path is fired automatically by the wire-version gate, so two triggers for one
// node can genuinely overlap. Without the inflight check they would race on the
// SAME box — one uploading a binary over the file another is about to restart the
// agent from. The second call must be refused, not queued.
func TestTriggerUpgradeRejectsSecondJobOnSameNode(t *testing.T) {
	release := make(chan struct{})
	var dialed int
	var mu sync.Mutex
	m, _ := upgradeManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		mu.Lock()
		dialed++
		mu.Unlock()
		<-release // hold the first upgrade open so the second call overlaps it
		return readyMock(), nil
	})

	if err := m.TriggerUpgrade("exit-de-1"); err != nil {
		t.Fatalf("first trigger: %v", err)
	}
	err := m.TriggerUpgrade("exit-de-1")
	if err == nil {
		t.Fatal("a second upgrade of the same node must be refused while one is in flight")
	}
	if !strings.Contains(err.Error(), "in flight") {
		t.Errorf("error %q should say a job is already in flight", err)
	}

	close(release)
	m.Wait()

	mu.Lock()
	defer mu.Unlock()
	if dialed != 1 {
		t.Errorf("dialed %d times, want exactly one upgrade to have run", dialed)
	}
}

// TestTriggerUpgradeClearsInflightAfterCompletion — the lock must be released
// however the job ends, or one failed upgrade would permanently wedge the node
// out of every future rollout.
func TestTriggerUpgradeClearsInflightAfterCompletion(t *testing.T) {
	m, _ := upgradeManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		return nil, errors.New("ssh refused")
	})
	if err := m.TriggerUpgrade("exit-de-1"); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if err := m.TriggerUpgrade("exit-de-1"); err != nil {
		t.Fatalf("a node whose upgrade failed must be retryable, got: %v", err)
	}
	m.Wait()
}

// TestTriggerUpgradeRecordsBackgroundFailure — the upgrade runs in a goroutine, so
// its error has no caller to return to. If it were only logged, an operator
// looking at the node in the UI would see a healthy row while the upgrade silently
// never happened. It must land on the node's LastError.
func TestTriggerUpgradeRecordsBackgroundFailure(t *testing.T) {
	m, st := upgradeManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		return nil, errors.New("ssh dial: i/o timeout")
	})
	if err := st.UpsertNode(context.Background(), domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit}); err != nil {
		t.Fatal(err)
	}
	if err := m.TriggerUpgrade("exit-de-1"); err != nil {
		t.Fatal(err)
	}
	m.Wait()

	n, err := st.GetNode(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if n.LastError == "" {
		t.Fatal("a background upgrade failure must be visible on the node, not only in the log")
	}
	if !strings.Contains(n.LastError, "timeout") {
		t.Errorf("LastError = %q, want it to carry the cause", n.LastError)
	}
}

// TestTriggerUpgradeRefusesWithoutAgentBinary — without controller.agent_bin there
// is nothing to install, and discovering that inside the goroutine would turn a
// configuration mistake into a background failure the operator has to go hunting
// for. Fail synchronously, at the call.
func TestTriggerUpgradeRefusesWithoutAgentBinary(t *testing.T) {
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	ca, _ := pki.NewCA("test-ca")
	m := New(st, ca, testFleet(), Options{ControllerEndpoint: "ctl:8443"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := m.TriggerUpgrade("exit-de-1")
	if err == nil || !strings.Contains(err.Error(), "agent binary") {
		t.Errorf("error = %v, want a synchronous complaint about the missing agent binary", err)
	}
}

// TestTriggerUpgradeRefusesUnknownNode — a node with no manifest entry or no ssh
// target cannot be upgraded, and saying so at the call beats a goroutine that
// fails on a nil dial.
func TestTriggerUpgradeRefusesUnknownNode(t *testing.T) {
	m, _ := upgradeManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		t.Error("must not dial an unknown node")
		return nil, nil
	})
	if err := m.TriggerUpgrade("not-in-manifest"); err == nil {
		t.Error("an unknown node must be refused")
	}
}
