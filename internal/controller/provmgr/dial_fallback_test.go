package provmgr

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/domain"
)

type stubRunner struct{ provisioner.Runner }

func (stubRunner) Close() error { return nil }

func fallbackManager(dial DialFunc) *Manager {
	return &Manager{opts: Options{Dial: dial}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestDialNodeFallsBackToMgmtAddrWhenPublicPathFails — a node whose public SSH
// path is dead but whose overlay address answers must still be reachable for an
// upgrade. An exit can complete the TCP three-way on its public address and then
// time out in the SSH handshake; without the fallback the rollout skips it while
// the controller is talking to it over the overlay the whole time.
func TestDialNodeFallsBackToMgmtAddrWhenPublicPathFails(t *testing.T) {
	// Arrange
	var dialled []string
	m := fallbackManager(func(target domain.SSHTarget) (provisioner.Runner, error) {
		dialled = append(dialled, target.Host)
		if target.Host == "203.0.113.7" {
			return nil, errors.New("ssh: handshake failed: i/o timeout")
		}
		return stubRunner{}, nil
	})
	node := domain.Node{Name: "exit-a", MgmtAddr: "10.0.0.7",
		SSH: domain.SSHTarget{Host: "203.0.113.7", Port: 2222, User: "root", KeyPath: "k"}}

	// Act
	runner, err := m.dialNode(context.Background(), node)

	// Assert
	if err != nil || runner == nil {
		t.Fatalf("dialNode = (%v, %v), want a runner over the mgmt address", runner, err)
	}
	if got := strings.Join(dialled, ","); got != "203.0.113.7,10.0.0.7" {
		t.Errorf("dialled %q, want the public address first and the mgmt address second", got)
	}
}

// TestDialNodeReportsBothFailures — when neither path answers the operator must
// see both, not only the fallback's error.
func TestDialNodeReportsBothFailures(t *testing.T) {
	m := fallbackManager(func(target domain.SSHTarget) (provisioner.Runner, error) {
		return nil, errors.New("down via " + target.Host)
	})
	node := domain.Node{Name: "exit-a", MgmtAddr: "10.0.0.7", SSH: domain.SSHTarget{Host: "203.0.113.7"}}

	_, err := m.dialNode(context.Background(), node)

	if err == nil || !strings.Contains(err.Error(), "down via 203.0.113.7") || !strings.Contains(err.Error(), "down via 10.0.0.7") {
		t.Errorf("err = %v, want both dial failures named", err)
	}
}

// TestDialNodeDoesNotRetryTheSameAddress — a node already managed over its mgmt
// address (or with none) has no second path; dialling it twice only doubles the wait.
func TestDialNodeDoesNotRetryTheSameAddress(t *testing.T) {
	for _, mgmt := range []string{"", "10.0.0.7"} {
		calls := 0
		m := fallbackManager(func(domain.SSHTarget) (provisioner.Runner, error) {
			calls++
			return nil, errors.New("down")
		})
		node := domain.Node{Name: "exit-a", MgmtAddr: mgmt, SSH: domain.SSHTarget{Host: "10.0.0.7"}}

		if _, err := m.dialNode(context.Background(), node); err == nil {
			t.Fatal("want an error")
		}
		if calls != 1 {
			t.Errorf("mgmt=%q: dialled %d times, want 1", mgmt, calls)
		}
	}
}
