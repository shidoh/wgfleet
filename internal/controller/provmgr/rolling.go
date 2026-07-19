package provmgr

import (
	"context"
	"fmt"
	"os"

	"github.com/shidoh/wgfleet/internal/controller/provisioner"
)

// UpgradeAgentVerified rolls one node's agent binary forward over SSH and returns
// the version.Short() identity of the binary now installed, read back off the node
// itself. The rolling-upgrade coordinator gates on that string appearing in the
// node's next check-in, so it must come from the binary that actually landed —
// not from what the controller believes it uploaded.
//
// It takes the per-node inflight lock for the whole operation, so it cannot race
// a UI-triggered upgrade or the version gate's auto-upgrade of the same node.
func (m *Manager) UpgradeAgentVerified(ctx context.Context, nodeID string) (string, error) {
	if err := m.acquire(nodeID); err != nil {
		return "", err
	}
	defer m.clearInflight(nodeID)

	node, _, ok := m.findNode(nodeID)
	if !ok {
		return "", fmt.Errorf("node %q not found in fleet manifest", nodeID)
	}
	if node.SSH.Host == "" || node.SSH.KeyPath == "" {
		return "", fmt.Errorf("node %q has no ssh target", nodeID)
	}
	if m.opts.AgentBinPath == "" {
		return "", fmt.Errorf("no agent binary configured (set controller.agent_bin)")
	}
	bin, err := os.ReadFile(m.opts.AgentBinPath)
	if err != nil {
		return "", fmt.Errorf("read agent binary: %w", err)
	}

	runner, err := m.opts.Dial(node.SSH)
	if err != nil {
		return "", fmt.Errorf("ssh dial %q: %w", node.Name, err)
	}
	defer func() { _ = runner.Close() }()

	p := provisioner.New(m.log)
	in := provisioner.BootstrapInput{Node: node, AgentBinary: bin}
	if _, err := p.Upgrade(ctx, runner, in, provisioner.ModeApply); err != nil {
		return "", err
	}
	return provisioner.ProbeAgentVersion(ctx, runner)
}

// RollbackAgent restores the binary the last upgrade displaced on a node and
// restarts it. Deliberately a separate SSH round trip from the upgrade: the
// upgrade's connection may be long gone (the coordinator waits minutes for the
// node to come back before giving up on it), and the whole premise of automatic
// rollback is that this path does not depend on anything the upgrade left working.
func (m *Manager) RollbackAgent(ctx context.Context, nodeID string) error {
	if err := m.acquire(nodeID); err != nil {
		return err
	}
	defer m.clearInflight(nodeID)

	node, _, ok := m.findNode(nodeID)
	if !ok {
		return fmt.Errorf("node %q not found in fleet manifest", nodeID)
	}
	if node.SSH.Host == "" || node.SSH.KeyPath == "" {
		return fmt.Errorf("node %q has no ssh target", nodeID)
	}

	runner, err := m.opts.Dial(node.SSH)
	if err != nil {
		return fmt.Errorf("ssh dial %q: %w", node.Name, err)
	}
	defer func() { _ = runner.Close() }()

	_, err = provisioner.New(m.log).Rollback(ctx, runner, node.Name, provisioner.ModeApply)
	return err
}

// acquire takes the per-node inflight lock, refusing when another
// provisioning/upgrade job already holds it.
func (m *Manager) acquire(nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inflight[nodeID] {
		return fmt.Errorf("node %q already has a provisioning/upgrade job in flight", nodeID)
	}
	m.inflight[nodeID] = true
	return nil
}
