package provmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/domain"
)

const fakeAgentBin = "\x7fELF-fake-binary"

// rollingMock answers the digest check with the digest of what was uploaded and
// the version probe with a recognizable build identity.
func rollingMock() *provisioner.MockRunner {
	m := provisioner.NewMockRunner()
	sum := sha256.Sum256([]byte(fakeAgentBin))
	m.PrefixResponses["sha256sum"] = hex.EncodeToString(sum[:]) + "  /usr/local/bin/wgfleet-agent"
	m.PrefixResponses["'/usr/local/bin/wgfleet-agent' --version"] =
		"wgfleet-agent v9 (commit cafe123, built x, go1.24)"
	return m
}

func withAgentBin(t *testing.T, m *Manager) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "wgfleet-agent")
	if err := os.WriteFile(bin, []byte(fakeAgentBin), 0o755); err != nil {
		t.Fatal(err)
	}
	m.opts.AgentBinPath = bin
}

func TestUpgradeAgentVerifiedReturnsTheVersionInstalledOnTheNode(t *testing.T) {
	mock := rollingMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	withAgentBin(t, m)

	got, err := m.UpgradeAgentVerified(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatalf("UpgradeAgentVerified: %v", err)
	}
	// Read back off the node, not assumed from what we uploaded — that is what
	// makes the rollout gate a proof rather than a guess.
	if want := "v9+cafe123"; got != want {
		t.Errorf("installed version = %q, want %q", got, want)
	}
	if _, ok := mock.Uploaded["/usr/local/bin/wgfleet-agent"]; !ok {
		t.Error("binary was not uploaded")
	}
	if !mock.RanCommand("cp -f '/usr/local/bin/wgfleet-agent' '/usr/local/bin/wgfleet-agent.prev'") {
		t.Errorf("no rollback snapshot was taken; ran %v", mock.Ran)
	}
}

func TestUpgradeAgentVerifiedReleasesTheInflightLock(t *testing.T) {
	mock := rollingMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	withAgentBin(t, m)

	// A rollout upgrades many nodes in sequence through the same Manager; a lock
	// leaked on the happy path would deadlock the second node onward.
	for i := range 2 {
		if _, err := m.UpgradeAgentVerified(context.Background(), "exit-de-1"); err != nil {
			t.Fatalf("pass %d: %v", i+1, err)
		}
	}
}

func TestUpgradeAgentVerifiedRefusesWhenANodeJobIsInFlight(t *testing.T) {
	mock := rollingMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })
	withAgentBin(t, m)

	if err := m.acquire("exit-de-1"); err != nil {
		t.Fatal(err)
	}
	defer m.clearInflight("exit-de-1")

	if _, err := m.UpgradeAgentVerified(context.Background(), "exit-de-1"); err == nil {
		t.Fatal("upgrade proceeded while another job held the per-node lock")
	}
}

func TestUpgradeAgentVerifiedRejectsUnknownNode(t *testing.T) {
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return rollingMock(), nil })
	withAgentBin(t, m)

	if _, err := m.UpgradeAgentVerified(context.Background(), "ghost"); err == nil {
		t.Fatal("unknown node was accepted")
	}
	// The lock must not be left held for a node the upgrade never touched.
	if err := m.acquire("ghost"); err != nil {
		t.Errorf("inflight lock leaked for a rejected node: %v", err)
	}
}

func TestRollbackAgentRestoresAndRestarts(t *testing.T) {
	mock := rollingMock()
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) { return mock, nil })

	// No AgentBinPath configured: rollback must not need one — it restores what is
	// already on the node, which is exactly why it still works when the upload path
	// is the thing that broke.
	if err := m.RollbackAgent(context.Background(), "exit-de-1"); err != nil {
		t.Fatalf("RollbackAgent: %v", err)
	}
	if !mock.RanCommand("cp -f '/usr/local/bin/wgfleet-agent.prev'") {
		t.Errorf("previous binary not restored; ran %v", mock.Ran)
	}
	if !mock.RanCommand("systemctl restart wgfleet-agent") {
		t.Error("agent not restarted after rollback")
	}
}
