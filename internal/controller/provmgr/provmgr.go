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
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// DialFunc opens a Runner to an SSH target. Injectable so tests use a mock.
type DialFunc func(target domain.SSHTarget) (provisioner.Runner, error)

// ProvisionObserver records the wall-clock duration of one apply-mode provisioning
// run, labelled by node role and outcome (err nil ⇒ success). It is injected so
// provmgr stays decoupled from the metrics package (which depends on the store);
// the controller passes metrics.ProvisionMetrics.ObserveProvision, while the CLI
// and tests leave it nil. now defaults to time.Now.
type ProvisionObserver func(role string, seconds float64, err error)

// Options configures the manager.
type Options struct {
	AgentBinPath       string // wgfleet-agent binary to install (optional)
	ControllerEndpoint string // mTLS endpoint the agent will dial
	Dial               DialFunc
	// OnProvision, when set, is called after every apply-mode Provision with its
	// duration and result. Plan (dry-run) runs are not timed (they execute nothing).
	OnProvision ProvisionObserver
}

// Manager runs provisioning jobs.
type Manager struct {
	store   store.Store
	ca      *pki.CA
	fleet   config.FleetSection
	opts    Options
	log     *slog.Logger
	now     func() time.Time // injectable clock for provisioning-duration timing
	baseCtx context.Context  // parent for async jobs; cancelled on controller shutdown

	// fleetMu guards fleet, which is no longer write-once: ForgetExit drops an entry
	// when the console deletes a node. Readers run on HTTP handler goroutines.
	fleetMu sync.RWMutex

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
		store: st, ca: ca, fleet: fleet, opts: opts, log: log, now: time.Now,
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

// ForgetExit drops an exit from the manifest view this Manager serves, after its
// declaration has been removed from the manifest FILE.
//
// The controller reads controller.yaml once at startup and never reloads it, so
// without this the deletion is invisible to the running process: ManifestNodes()
// keeps returning the exit, the console re-renders it as a Pending card seconds
// after the operator deleted it, and — because Provisionable() and findNode() read
// the same stale copy, SSH target and key path intact — the Provision button on
// that card still works. Provisioning has no confirmation step, so one click
// re-creates a node whose declaration is gone from disk; it then disappears for
// real at the next controller restart, as an outage with no apparent cause.
//
// Only exits: masters are not deletable from the console, and dropping the hub
// from the manifest view would strand every provisioning path that resolves it.
func (m *Manager) ForgetExit(name string) {
	m.fleetMu.Lock()
	defer m.fleetMu.Unlock()
	kept := make([]config.ExitConfig, 0, len(m.fleet.Exits))
	for _, e := range m.fleet.Exits {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	m.fleet.Exits = kept
}

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
	m.fleetMu.RLock()
	defer m.fleetMu.RUnlock()

	var out []domain.Node
	for _, mm := range m.fleet.Masters {
		n, _, _ := m.findNodeLocked(mm.Name)
		n.State = domain.StatePending
		out = append(out, n)
	}
	for _, e := range m.fleet.Exits {
		n, _, _ := m.findNodeLocked(e.Name)
		n.State = domain.StatePending
		out = append(out, n)
	}
	return out
}

// Provision runs the bootstrap pipeline synchronously and returns the report.
// In apply mode it times the whole run (including the async path, which calls
// here) and reports the duration + outcome via Options.OnProvision when set.
func (m *Manager) Provision(ctx context.Context, nodeID string, mode provisioner.Mode) (rep provisioner.Report, err error) {
	node, _, ok := m.findNode(nodeID)
	if !ok {
		return provisioner.Report{}, fmt.Errorf("node %q not found in fleet manifest", nodeID)
	}
	if node.SSH.Host == "" || node.SSH.KeyPath == "" {
		return provisioner.Report{}, fmt.Errorf("node %q has no ssh target", nodeID)
	}
	// Refuse BEFORE anything is issued or uploaded. Bootstrap installs the systemd
	// unit either way, so provisioning without a binary leaves a unit in a restart
	// loop with nothing to run and a node that never registers — and the bootstrap
	// reported that as a completed run, because the missing upload degraded to a
	// no-op "check" step. The two upgrade paths already refuse this state; apply-mode
	// provisioning is the one that told the operator it had worked. Plan mode still
	// renders, so previewing a node does not need the binary in hand.
	if mode == provisioner.ModeApply && m.opts.AgentBinPath == "" {
		return provisioner.Report{}, fmt.Errorf(
			"no agent binary configured (set controller.agent_bin, or pass --agent-bin): "+
				"provisioning %q would install the unit with nothing to run", nodeID)
	}

	// Time the apply only — a plan executes nothing, so its duration is noise. The
	// deferred record fires on every return below (cert error, dial error, success),
	// so the histogram counts both successful and failed bootstraps.
	if mode == provisioner.ModeApply && m.opts.OnProvision != nil {
		start := m.now()
		defer func() {
			m.opts.OnProvision(string(node.Role), m.now().Sub(start).Seconds(), err)
		}()
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
	// Snapshot the fleet under the read lock: these are value-receiver methods and
	// field reads on a struct ForgetExit can now mutate, and a value receiver copies
	// the whole FleetSection — slice header included — so reading it unguarded races
	// with a concurrent console delete.
	m.fleetMu.RLock()
	fleet := m.fleet
	m.fleetMu.RUnlock()

	in := provisioner.BootstrapInput{
		Node:                node,
		Bundle:              pki.KeyPair{CertPEM: bundle.CertPEM},
		NodeKey:             bundle.KeyPEM,
		CACert:              m.ca.CertPEM(),
		ControllerEndpoint:  m.opts.ControllerEndpoint,
		ZeroTierNetwork:     fleet.ZeroTierNetwork,
		MgmtOverlayMSS:      fleet.MgmtOverlayMSS,
		ReconcileInterval:   fleet.AgentReconcileInterval(),
		ASBlacklistV4URL:    fleet.ASBlacklistV4URL,
		ASBlacklistV6URL:    fleet.ASBlacklistV6URL,
		ASBlacklistInterval: fleet.ASBlacklistInterval,
		MgmtIgnoreCIDRs:     fleet.MgmtCIDRs(),
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
	// Take the per-node lock before touching the node. This is the THIRD entry point
	// that upgrades an agent — alongside the rollout coordinator
	// (UpgradeAgentVerified) and the wire-version gate (TriggerUpgrade) — and it was
	// the only one unguarded, so `--upgrade-agent <node>` could drive a second
	// concurrent SSH upload+restart against a node a rolling upgrade was already
	// mid-way through. Plan mode executes nothing, so it stays lock-free: blocking a
	// dry-run behind a running upgrade would be user-hostile for no safety gain.
	if mode == provisioner.ModeApply {
		if err := m.acquire(nodeID); err != nil {
			return provisioner.Report{}, err
		}
		defer m.clearInflight(nodeID)
	}
	return m.upgradeAgentLocked(ctx, node, mode)
}

// upgradeAgentLocked performs the upload+restart assuming the caller ALREADY holds
// the node's inflight lock (or is in plan mode, which takes none).
//
// It exists because TriggerUpgrade must take the lock SYNCHRONOUSLY — its whole
// contract is to reject a duplicate at the call, before returning to the operator
// — and then hand the work to a goroutine. Routing that goroutine back through
// UpgradeAgent made it acquire a lock its own caller was already holding, so every
// TriggerUpgrade failed instantly with "already has a provisioning/upgrade job in
// flight" and never reached the node at all. That took out both of its callers:
// the Web UI's upgrade button and the wire-version gate's self-heal for an agent
// too old to be served a spec. Found by test, 2026-08-18.
func (m *Manager) upgradeAgentLocked(ctx context.Context, node domain.Node, mode provisioner.Mode) (provisioner.Report, error) {
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

	node, _, ok := m.findNode(nodeID)
	if !ok {
		return fmt.Errorf("node %q not found in fleet manifest", nodeID)
	}
	// Acquire SYNCHRONOUSLY: rejecting a duplicate is this call's contract, and the
	// caller (UI button, version gate) must learn about it here rather than from a
	// goroutine it cannot observe.
	if err := m.acquire(nodeID); err != nil {
		return err
	}

	bg := m.baseCtx
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer m.clearInflight(nodeID)
		// Locked variant on purpose — we hold the lock already. Calling UpgradeAgent
		// here would have it try to acquire it again and fail every single time.
		_, err := m.upgradeAgentLocked(bg, node, provisioner.ModeApply)
		if err == nil {
			// Uploading a binary and restarting a service is the FIRST HALF of an
			// upgrade. This path serves the Web UI's Upgrade button and the wire-gate's
			// automatic push, and both used to stop here: an agent that started and
			// could not converge logged "agent upgrade applied" and, worse, had its
			// LastError CLEARED — so the node went green in the console on the strength
			// of a successful scp. Only --upgrade-agent waited. Now all of them do.
			err = m.awaitAfterUpgrade(bg, nodeID)
		}
		// Record the outcome on the node so a background upgrade failure is visible
		// in the UI (the detail page surfaces Node.LastError) instead of being
		// swallowed into a log line the operator never sees. Success clears it.
		m.recordUpgradeOutcome(bg, nodeID, err)
		if err != nil {
			m.log.Error("agent upgrade failed", "node", nodeID, "err", err)
			return
		}
		m.log.Info("agent upgrade confirmed", "node", nodeID)
	}()
	return nil
}

// awaitAfterUpgrade confirms the node came back on the binary we just installed.
//
// restartedAt is taken HERE, after the upload and restart have returned, not before
// them: the upload takes tens of seconds over SSH, so a "restartedAt" captured
// before it is satisfied by a report from the very process the upgrade is replacing.
// Re-running an upgrade with the same version to unstick a node then printed
// "confirmed" on the strength of the old agent checking in mid-transfer.
func (m *Manager) awaitAfterUpgrade(ctx context.Context, nodeID string) error {
	restartedAt := time.Now()
	want, err := provisioner.ProbeLocalAgentVersion(ctx, m.opts.AgentBinPath)
	if err != nil {
		// We upgraded but cannot say to what, so we cannot confirm it either. Say so
		// rather than claim success.
		return fmt.Errorf("upgraded but cannot identify the binary to confirm against: %w", err)
	}
	return m.AwaitAgentBackAsBefore(ctx, nodeID, want, restartedAt, upgradeConfirmTimeout, upgradeReportFresh)
}

// AwaitAgentBackAsBefore is AwaitAgentBack with the bar set by the state the node
// last reported BEFORE the restart — which is what the store still holds at this
// point, because the new process has not checked in yet. A node that went in
// Degraded is back when it is Degraded on the new version; see
// domain.Node.AgentBackReasonFrom for why demanding Ready of it made the one node
// that needed a fix the one node that could never take it.
func (m *Manager) AwaitAgentBackAsBefore(ctx context.Context, nodeID, want string, restartedAt time.Time, timeout, freshWithin time.Duration) error {
	before := domain.StateReady
	if m.store != nil {
		if n, err := m.store.GetNode(ctx, nodeID); err == nil && !n.LastSeen.After(restartedAt) {
			before = n.State
		}
	}
	return m.AwaitAgentBackFrom(ctx, nodeID, before, want, restartedAt, timeout, freshWithin)
}

// How long to wait for a node to report in on its new binary, and how recent that
// report has to be. Shared by every upgrade path so they cannot drift apart.
const (
	upgradeConfirmTimeout = 3 * time.Minute
	upgradeReportFresh    = 2 * time.Minute
)

// recordUpgradeOutcome stamps a background agent-upgrade result onto the node's
// LastError (preserving its operational state): the error message on failure, or
// an empty string clearing a prior failure on success. Best-effort — a store
// error here is logged, never fatal to the upgrade path.
func (m *Manager) recordUpgradeOutcome(ctx context.Context, nodeID string, upErr error) {
	if m.store == nil {
		return
	}
	n, err := m.store.GetNode(ctx, nodeID)
	if err != nil {
		m.log.Warn("could not load node to record upgrade outcome", "node", nodeID, "err", err)
		return
	}
	msg := ""
	if upErr != nil {
		msg = "agent upgrade failed: " + upErr.Error()
	}
	if err := m.store.SetNodeState(ctx, nodeID, n.State, msg); err != nil {
		m.log.Warn("could not record upgrade outcome", "node", nodeID, "err", err)
	}
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
	// Provisioning is the operator saying "this node, again": it lifts a delete.
	if err := m.store.Readmit(ctx, node.ID); err != nil {
		return err
	}
	if existing, err := m.store.GetNode(ctx, node.ID); err == nil {
		existing.State = state
		existing.LastError = ""
		existing.Decommission = false
		existing.Drain = false
		// Refresh the fields the MANIFEST owns. Keeping the existing row wholesale
		// pinned public_ip to whatever the node had when it was first onboarded: a node
		// that changed address kept the old one in the console, because nothing else
		// ever writes it (the agent advertises a public IP only under --public-ip,
		// which no installed unit passes). Only non-empty manifest values overwrite —
		// except Role, which the manifest always states and Register rewrites on every
		// pass anyway — so a node the manifest is silent about keeps what it has.
		//
		// mgmt_addr is refreshed too even though Register keeps it fresh on its own:
		// provisioning is about to write this very value into the node's agent.yaml,
		// so the manifest is what the agent will report from here on.
		if node.PublicIP != "" {
			existing.PublicIP = node.PublicIP
		}
		if node.MgmtAddr != "" {
			existing.MgmtAddr = node.MgmtAddr
		}
		if node.Region != "" {
			existing.Region = node.Region
		}
		existing.Role = node.Role
		if node.SSH.Host != "" {
			existing.SSH = node.SSH
		}
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
	m.fleetMu.RLock()
	defer m.fleetMu.RUnlock()
	return m.findNodeLocked(name)
}

// findNodeLocked is findNode for callers that ALREADY hold fleetMu. It exists
// because sync.RWMutex forbids recursive read locking: the mutex is
// writer-preferring, so once a writer (ForgetExit) queues, it blocks new readers —
// including a second RLock on the goroutine that already holds the first. That
// goroutine cannot release the outer lock until the inner one is granted, and the
// inner one waits for the writer, which waits for the outer. ManifestNodes used to
// call the locking findNode from inside its own read section, which wedged every
// dashboard render the moment a node delete raced a page load.
func (m *Manager) findNodeLocked(name string) (domain.Node, config.SSHConfig, bool) {
	for _, mm := range m.fleet.Masters {
		if mm.Name == name {
			return domain.Node{
				ID: mm.Name, Name: mm.Name, Role: domain.RoleMaster,
				// A master's public address is public_ip and nothing else. Unlike an
				// exit's — which the MASTER dials, so ssh.host is a sane default — this
				// one is what END USERS dial, and ssh.host is often the management
				// overlay. Defaulting it here laundered the overlay address into the
				// store, where the console displays it as PUBLIC and the keybroker's
				// fallback would hand it to every client profile — right past
				// clientcfg.EndpointHost, which refuses ssh.host on purpose. Empty is
				// the honest answer; the client pages say "no public endpoint (public_ip)".
				MgmtAddr: mm.MgmtAddr, PublicIP: mm.PublicIP,
				SSH: toSSHTarget(mm.SSH),
			}, mm.SSH, true
		}
	}
	for _, e := range m.fleet.Exits {
		if e.Name == name {
			return domain.Node{
				ID: e.Name, Name: e.Name, Role: domain.RoleExit, Region: e.Region,
				MgmtAddr: e.MgmtAddr, PublicIP: publicIP(e.PublicIP, e.SSH.Host),
				Drain: e.Drain, DrainByConfig: e.Drain,
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

// AwaitAgentBack waits for a node to report in on the version it was just upgraded
// to, and returns why it did not when it did not.
//
// It exists because uploading a binary and restarting a service is not an upgrade:
// it is the first half of one. Three of the four paths that upgrade an agent —
// --upgrade-agent, the Web UI button and the wire-version gate's automatic push —
// did exactly that and then reported success, so an agent that started and could not
// converge looked identical to one that worked, and the operator found out later
// from something else entirely. The rolling upgrade was the only caller that
// checked; the check is the same one, taken from domain.Node. All four call it now
// (the UI button and the version gate through TriggerUpgrade → awaitAfterUpgrade),
// and the earlier version of this paragraph claimed that before it was true.
//
// It does not roll back. The coordinator does that because it is walking a fleet and
// must not leave a half-upgraded one behind; a single-node upgrade the operator
// asked for is theirs to decide about, and a surprise downgrade to whatever
// .prev happens to be is not obviously the kinder outcome. Saying plainly what
// happened is.
func (m *Manager) AwaitAgentBack(ctx context.Context, nodeID, want string, restartedAt time.Time, timeout, freshWithin time.Duration) error {
	return m.AwaitAgentBackFrom(ctx, nodeID, domain.StateReady, want, restartedAt, timeout, freshWithin)
}

// AwaitAgentBackFrom is AwaitAgentBack with the bar set by the node's state before
// the upgrade (see domain.Node.AgentBackReasonFrom): a node that went in Degraded
// has come back when it reports Degraded on the new version.
func (m *Manager) AwaitAgentBackFrom(ctx context.Context, nodeID string, before domain.NodeState, want string, restartedAt time.Time, timeout, freshWithin time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		node, err := m.store.GetNode(ctx, nodeID)
		switch {
		case err != nil:
			last = "cannot read the node: " + err.Error()
		default:
			if last = node.AgentBackReasonFrom(before, want, restartedAt, time.Now(), freshWithin); last == "" {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not come back on %s within %s: %s. It is running whatever it "+
				"started; check `journalctl -u wgfleet-agent` on the node, and roll back with the "+
				"previous binary at /usr/local/bin/wgfleet-agent.prev if it cannot converge",
				nodeID, want, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
