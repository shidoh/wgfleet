package provmgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// The per-node deadline has to hold even when the dial itself does not honour it.
// Bounding the SSH handshake (provisioner.DialSSH) fixes the case we have HIT; it
// does not make the deadline enforceable, because any Dial implementation — a
// custom one, a future library change, a DNS resolver with no timeout — can still
// block past it. A deadline the caller cannot enforce is not a deadline, which is
// exactly what left a rolling upgrade sitting 13 minutes on one node.
func TestUpgradeAgentVerifiedAbandonsADialThatOutlivesTheDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		<-release // a dial that never comes back on its own
		return rollingMock(), nil
	})
	withAgentBin(t, m)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := m.UpgradeAgentVerified(ctx, "exit-de-1")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a dial that never returns must not read as a successful upgrade")
		}
		// And it must be tagged UNTOUCHED: a node we never reached must not be
		// "rolled back" onto whatever snapshot an earlier upgrade left there — that
		// is a silent downgrade, and it is how a dial timeout once put a node back on
		// a week-old binary.
		var u interface{ NodeUntouched() bool }
		if !errors.As(err, &u) || !u.NodeUntouched() {
			t.Errorf("a dial that timed out never touched the node, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpgradeAgentVerified ignored its context and blocked on the dial")
	}

	// The inflight lock must be released too, or the node is unupgradable until the
	// controller restarts.
	if err := m.acquire("exit-de-1"); err != nil {
		t.Errorf("inflight lock still held after an abandoned dial: %v", err)
	}
	m.clearInflight("exit-de-1")
}

// Same guarantee on the way back: a rollback is the recovery path, and one that
// can block forever leaves the coordinator unable to finish or report.
func TestRollbackAgentAbandonsADialThatOutlivesTheDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	m, _ := newManager(t, func(domain.SSHTarget) (provisioner.Runner, error) {
		<-release
		return rollingMock(), nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.RollbackAgent(ctx, "exit-de-1") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a rollback whose dial never returned must not report success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RollbackAgent ignored its context and blocked on the dial")
	}
}
