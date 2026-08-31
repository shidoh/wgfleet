package provmgr

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/provisioner"
)

// Provisioning without an agent binary produces a node with a systemd unit and
// nothing to run: the unit sits in activating/failed forever and the node never
// registers. The bootstrap used to emit a no-op "check" step for this and report
// `bootstrap complete`, so the operator was told the node was provisioned. The two
// upgrade paths already refuse the same state loudly; apply-mode provisioning must
// too. Plan mode still renders, so a preview does not need the binary.
func TestProvisionApplyRefusesWithoutAnAgentBinary(t *testing.T) {
	m := New(nil, nil, testFleet(), Options{ControllerEndpoint: "ctl:8443"}, slog.New(slog.DiscardHandler))

	_, err := m.Provision(context.Background(), "exit-de-1", provisioner.ModeApply)

	if err == nil {
		t.Fatal("apply-mode provisioning succeeded with no agent binary — the node would never run an agent")
	}
	if !strings.Contains(err.Error(), "agent_bin") {
		t.Errorf("error does not name the setting to fix: %v", err)
	}
}
