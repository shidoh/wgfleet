// Package provmgr drives node provisioning from the serving controller, both
// synchronously (the CLI `--provision`) and asynchronously (a Web UI button).
// It resolves the node's SSH target from the fleet manifest, issues its mTLS
// bundle from the CA, and runs the SSH bootstrap pipeline (internal/controller/
// provisioner), tracking lifecycle state in the store.
package provmgr

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// DialFunc opens a Runner to an SSH target. Injectable so tests use a mock.
type DialFunc func(target domain.SSHTarget) (provisioner.Runner, error)

// Options configures the manager.
type Options struct {
	AgentBinPath       string // wgfleet-agent binary to install (optional)
	ControllerEndpoint string // mTLS endpoint the agent will dial
	Dial               DialFunc
}

// Manager runs provisioning jobs.
type Manager struct {
	store   store.Store
	ca      *pki.CA
	fleet   config.FleetSection
	opts    Options
	log     *slog.Logger
	baseCtx context.Context // parent for async jobs; cancelled on controller shutdown

	mu       sync.Mutex
	inflight map[string]bool
	wg       sync.WaitGroup // tracks in-flight async jobs for graceful drain
}

// New builds a Manager. dial defaults to a real SSH dialer when nil. Call
// SetBaseContext with the controller's signal context so async jobs are
// cancelled on shutdown; otherwise they run under context.Background().
func New(st store.Store, ca *pki.CA, fleet config.FleetSection, opts Options, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	if opts.Dial == nil {
		opts.Dial = func(t domain.SSHTarget) (provisioner.Runner, error) {
			return provisioner.DialSSH(t, nil)
		}
	}
	return &Manager{
		store: st, ca: ca, fleet: fleet, opts: opts, log: log,
		baseCtx: context.Background(), inflight: map[string]bool{},
	}
}

// SetBaseContext sets the parent context for async provisioning jobs. Pass the
// controller's signal context so jobs abort promptly on SIGTERM instead of
// running on after the store is closed.
func (m *Manager) SetBaseContext(ctx context.Context) {
	if ctx != nil {
		m.baseCtx = ctx
	}
}

// Wait blocks until all in-flight async provisioning jobs have finished. Call it
// during shutdown (after the base context is cancelled) before closing the store,
// so a background job cannot write to a closed database.
func (m *Manager) Wait() { m.wg.Wait() }

// Provisionable reports whether a node exists in the fleet manifest with an SSH
// target — i.e. whether it can be provisioned at all.
func (m *Manager) Provisionable(nodeID string) bool {
	node, ssh, ok := m.findNode(nodeID)
	return ok && node.SSH.Host != "" && ssh.KeyPath != ""
}

// ManifestNodes returns every node declared in the fleet manifest as a Pending
// inventory stub. The dashboard merges these with the live store so an operator
// can see (and provision) declared-but-not-yet-provisioned nodes.
func (m *Manager) ManifestNodes() []domain.Node {
	var out []domain.Node
	for _, mm := range m.fleet.Masters {
		n, _, _ := m.findNode(mm.Name)
		n.State = domain.StatePending
		out = append(out, n)
	}
	for _, e := range m.fleet.Exits {
		n, _, _ := m.findNode(e.Name)
		n.State = domain.StatePending
		out = append(out, n)
	}
	return out
}

// Provision runs the bootstrap pipeline synchronously and returns the report.
func (m *Manager) Provision(ctx context.Context, nodeID string, mode provisioner.Mode) (provisioner.Report, error) {
	node, _, ok := m.findNode(nodeID)
	if !ok {
		return provisioner.Report{}, fmt.Errorf("node %q not found in fleet manifest", nodeID)
	}
	if node.SSH.Host == "" || node.SSH.KeyPath == "" {
		return provisioner.Report{}, fmt.Errorf("node %q has no ssh target", nodeID)
	}

	// Persist the manifest's inventory (mgmt_addr, public_ip, role) into the store
	// so the keybroker can render endpoints from it. The agent's later Register
	// preserves these (it only overwrites with non-empty values, which the systemd
	// unit does not send). Apply mode only — a dry-run must not mutate the store.
	if mode == provisioner.ModeApply && m.store != nil {
		if err := m.ensureNode(ctx, node, domain.StateProvisioning); err != nil {
			return provisioner.Report{}, fmt.Errorf("persist node inventory: %w", err)
		}
	}

	bundle, err := m.ca.IssueNodeCert(node.ID)
	if err != nil {
		return provisioner.Report{}, fmt.Errorf("issue node cert: %w", err)
	}
	in := provisioner.BootstrapInput{
		Node:                node,
		Bundle:              pki.KeyPair{CertPEM: bundle.CertPEM},
		NodeKey:             bundle.KeyPEM,
		CACert:              m.ca.CertPEM(),
		ControllerEndpoint:  m.opts.ControllerEndpoint,
		ZeroTierNetwork:     m.fleet.ZeroTierNetwork,
		MgmtOverlayMSS:      m.fleet.MgmtOverlayMSS,
		ReconcileInterval:   m.fleet.AgentReconcileInterval(),
		ASBlacklistV4URL:    m.fleet.ASBlacklistV4URL,
		ASBlacklistV6URL:    m.fleet.ASBlacklistV6URL,
		ASBlacklistInterval: m.fleet.ASBlacklistInterval,
		MgmtIgnoreCIDRs:     m.fleet.MgmtCIDRs(),
	}
	if m.opts.AgentBinPath != "" {
		bin, err := os.ReadFile(m.opts.AgentBinPath)
		if err != nil {
			return provisioner.Report{}, fmt.Errorf("read agent binary: %w", err)
		}
		in.AgentBinary = bin
	}

	runner, err := m.opts.Dial(node.SSH)
	if err != nil {
		return provisioner.Report{}, fmt.Errorf("ssh dial %q: %w", node.Name, err)
	}
	defer func() { _ = runner.Close() }()

	return provisioner.New(m.log).Provision(ctx, runner, in, mode)
}

// UpgradeAgent rolls a node's agent binary forward in place (upload + restart)
// over SSH, synchronously, returning the report. It reuses the node's manifest
// SSH target — the same channel bootstrap used — so the controller must still
// have SSH reach to the node. The mTLS identity is already on the node, so unlike
// Provision this needs no CA work.
func (m *Manager) UpgradeAgent(ctx context.Context, nodeID string, mode provisioner.Mode) (provisioner.Report, error) {
	node, _, ok := m.findNode(nodeID)
	if !ok {
		return provisioner.Report{}, fmt.Errorf("node %q not found in fleet manifest", nodeID)
	}
	if node.SSH.Host == "" || node.SSH.KeyPath == "" {
		return provisioner.Report{}, fmt.Errorf("node %q has no ssh target", nodeID)
	}
	if m.opts.AgentBinPath == "" {
		return provisioner.Report{}, fmt.Errorf("no agent binary configured (set controller.agent_bin)")
	}
	bin, err := os.ReadFile(m.opts.AgentBinPath)
	if err != nil {
		return provisioner.Report{}, fmt.Errorf("read agent binary: %w", err)
	}

	runner, err := m.opts.Dial(node.SSH)
	if err != nil {
		return provisioner.Report{}, fmt.Errorf("ssh dial %q: %w", node.Name, err)
	}
	defer func() { _ = runner.Close() }()

	in := provisioner.BootstrapInput{Node: node, AgentBinary: bin}
	return provisioner.New(m.log).Upgrade(ctx, runner, in, mode)
}

// TriggerUpgrade starts a background agent upgrade for a node, deduped per node.
// It satisfies grpcapi.UpgradeTrigger so the controller's version gate can roll
// an incompatible (too-old) agent forward without operator action. It returns an
// error only for synchronous preconditions (node unknown / not upgradable / a job
// already in flight).
func (m *Manager) TriggerUpgrade(nodeID string) error {
	if !m.Provisionable(nodeID) {
		return fmt.Errorf("node %q is not upgradable (missing fleet entry or ssh target)", nodeID)
	}
	if m.opts.AgentBinPath == "" {
		return fmt.Errorf("no agent binary configured (set controller.agent_bin)")
	}

	m.mu.Lock()
	if m.inflight[nodeID] {
		m.mu.Unlock()
		return fmt.Errorf("node %q already has a provisioning/upgrade job in flight", nodeID)
	}
	m.inflight[nodeID] = true
	m.mu.Unlock()

	bg := m.baseCtx
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.clearInflight(nodeID)
		if _, err := m.UpgradeAgent(bg, nodeID, provisioner.ModeApply); err != nil {
			m.log.Error("agent upgrade failed", "node", nodeID, "err", err)
			return
		}
		m.log.Info("agent upgrade applied; restarted agent will re-register", "node", nodeID)
	}()
	return nil
}

// TriggerAsync starts an apply-mode provisioning job in the background. It
// dedupes concurrent jobs per node, sets the node Provisioning immediately, then
// transitions it to Reconciling on success (the agent takes over) or Error on
// failure. It returns an error only for the synchronous preconditions.
func (m *Manager) TriggerAsync(nodeID string) error {
	if !m.Provisionable(nodeID) {
		return fmt.Errorf("node %q is not provisionable (missing fleet entry or ssh target)", nodeID)
	}

	m.mu.Lock()
	if m.inflight[nodeID] {
		m.mu.Unlock()
		return fmt.Errorf("node %q is already provisioning", nodeID)
	}
	m.inflight[nodeID] = true
	m.mu.Unlock()

	node, _, _ := m.findNode(nodeID)
	bg := m.baseCtx
	if err := m.ensureNode(bg, node, domain.StateProvisioning); err != nil {
		m.clearInflight(nodeID)
		return fmt.Errorf("mark provisioning: %w", err)
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.clearInflight(nodeID)
		_, err := m.Provision(bg, nodeID, provisioner.ModeApply)
		if err != nil {
			m.log.Error("provisioning failed", "node", nodeID, "err", err)
			m.setState(bg, nodeID, domain.StateError, err.Error())
			return
		}
		m.log.Info("provisioning applied; agent will take over", "node", nodeID)
		m.setState(bg, nodeID, domain.StateReconciling, "")
	}()
	return nil
}

// setState persists a node lifecycle transition, logging (never swallowing) a
// store error so a failed transition — e.g. the store closed mid-shutdown — is
// visible instead of leaving the node stuck in its prior state with no trace.
func (m *Manager) setState(ctx context.Context, nodeID string, state domain.NodeState, detail string) {
	if err := m.store.SetNodeState(ctx, nodeID, state, detail); err != nil {
		m.log.Error("failed to persist provisioning state transition",
			"node", nodeID, "state", state, "err", err)
	}
}

// ensureNode upserts the node into inventory (from the manifest) at the given
// state, preserving an existing row's identity. It is only ever called to START
// provisioning, which means "bring this node UP" — so it CLEARS any pending
// teardown (Decommission) or Drain intent. Without this, re-provisioning a
// decommissioned node leaves Decommission=true in the store; the keybroker keeps
// rendering NodeSpec.Decommission=true, and the (still mTLS-identified) agent tears
// its data plane down on every reconcile instead of converging — an endless
// "decommission complete" loop that never comes back up (observed live 2026-06-18).
func (m *Manager) ensureNode(ctx context.Context, node domain.Node, state domain.NodeState) error {
	if existing, err := m.store.GetNode(ctx, node.ID); err == nil {
		existing.State = state
		existing.LastError = ""
		existing.Decommission = false
		existing.Drain = false
		return m.store.UpsertNode(ctx, existing)
	}
	node.State = state
	return m.store.UpsertNode(ctx, node)
}

func (m *Manager) clearInflight(nodeID string) {
	m.mu.Lock()
	delete(m.inflight, nodeID)
	m.mu.Unlock()
}

// findNode resolves a node name to its domain.Node + SSH target from the fleet
// manifest (master or exit).
func (m *Manager) findNode(name string) (domain.Node, config.SSHConfig, bool) {
	for _, mm := range m.fleet.Masters {
		if mm.Name == name {
			return domain.Node{
				ID: mm.Name, Name: mm.Name, Role: domain.RoleMaster,
				MgmtAddr: mm.MgmtAddr, PublicIP: publicIP(mm.PublicIP, mm.SSH.Host),
				SSH: toSSHTarget(mm.SSH),
			}, mm.SSH, true
		}
	}
	for _, e := range m.fleet.Exits {
		if e.Name == name {
			return domain.Node{
				ID: e.Name, Name: e.Name, Role: domain.RoleExit, Region: e.Region,
				MgmtAddr: e.MgmtAddr, PublicIP: publicIP(e.PublicIP, e.SSH.Host),
				SSH: toSSHTarget(e.SSH),
			}, e.SSH, true
		}
	}
	return domain.Node{}, config.SSHConfig{}, false
}

// publicIP resolves a node's advertised public IP: the explicit manifest value,
// or the SSH host when unset (for typical setups where you SSH to the node at
// its public IP). It must be set explicitly when SSH goes via a bastion or a
// forwarded local port (e.g. Lima), where ssh.host is not the peer endpoint.
func publicIP(explicit, sshHost string) string {
	if explicit != "" {
		return explicit
	}
	return sshHost
}

func toSSHTarget(s config.SSHConfig) domain.SSHTarget {
	return domain.SSHTarget{
		Host: s.Host, Port: s.Port, User: s.User,
		KeyPath:               config.ExpandPath(s.KeyPath), // ~ is not expanded by os.ReadFile
		HostKey:               s.HostKey,
		InsecureIgnoreHostKey: s.InsecureIgnoreHostKey,
	}
}
