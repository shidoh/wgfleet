package rollout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Phase is where one node stands in the rollout. It is what the UI renders per
// row and what the CLI streams.
type Phase string

const (
	PhasePending    Phase = "pending"
	PhaseUploading  Phase = "uploading"
	PhaseVerifying  Phase = "verifying"
	PhaseRestarting Phase = "restarting"
	PhaseConfirming Phase = "confirming"
	PhaseDone       Phase = "done"
	PhaseFailed     Phase = "failed"
	PhaseRolledBack Phase = "rolled-back"
	// PhaseSkipped marks nodes never touched because an earlier node failed. The
	// rollout stops on first failure, so these stay exactly as they were.
	PhaseSkipped Phase = "skipped"
)

// Terminal reports whether no further transition is expected.
func (p Phase) Terminal() bool {
	switch p {
	case PhaseDone, PhaseFailed, PhaseRolledBack, PhaseSkipped:
		return true
	}
	return false
}

// NodeProgress is one node's live state within a rollout.
type NodeProgress struct {
	Target
	Phase      Phase
	Installed  string // version probed off the node after upload ("" until verified)
	Err        string
	RolledBack bool
	StartedAt  time.Time
	EndedAt    time.Time
}

// State is a point-in-time snapshot of a rollout, safe to hand to a template or
// serialize. Snapshot() returns a deep copy so a reader never observes a torn view.
type State struct {
	Active     bool
	Aborted    bool
	Want       string
	StartedAt  time.Time
	EndedAt    time.Time
	Nodes      []NodeProgress
	Err        string
	Skipped    []Skipped
	LastUpdate time.Time
}

// Done reports how many nodes finished successfully.
func (s State) Done() int { return s.count(PhaseDone) }

// Total is how many nodes the rollout set out to touch.
func (s State) Total() int { return len(s.Nodes) }

func (s State) count(p Phase) int {
	n := 0
	for _, x := range s.Nodes {
		if x.Phase == p {
			n++
		}
	}
	return n
}

// Upgrader performs the per-node SSH work. *provmgr.Manager satisfies it.
type Upgrader interface {
	// UpgradeAgentVerified uploads + digest-verifies + restarts, returning the
	// version identity of the binary now on the node.
	UpgradeAgentVerified(ctx context.Context, nodeID string) (string, error)
	// RollbackAgent restores the binary the upgrade displaced and restarts.
	RollbackAgent(ctx context.Context, nodeID string) error
}

// NodeReader reads observed node state. store.Store satisfies it.
type NodeReader interface {
	GetNode(ctx context.Context, id string) (domain.Node, error)
}

// Config tunes the gate. Zero values fall back to the defaults below.
type Config struct {
	// ConfirmTimeout is how long a node has to come back Ready on the new version
	// before it is rolled back. Generous relative to an agent restart (seconds)
	// because the gate waits for a full status report, not for the process to exist.
	ConfirmTimeout time.Duration
	// PollInterval is how often the gate re-reads the node.
	PollInterval time.Duration
	// FreshWithin bounds how stale the node's LastSeen may be and still count as
	// "reporting now".
	FreshWithin time.Duration
	// LockPath is the cross-process rollout lock (see lock.go). Empty in Config
	// means DefaultLockPath; set it to "-" to disable locking entirely, which only
	// tests should do. The Coordinator's own Active flag guards one PROCESS; this
	// guards the fleet, because the serving controller and the --rolling-upgrade
	// CLI are separate processes with separate in-memory state.
	LockPath string
}

const (
	defaultConfirmTimeout = 3 * time.Minute
	defaultPollInterval   = 5 * time.Second
	defaultFreshWithin    = 90 * time.Second
	// DefaultFreshWithin is defaultFreshWithin for callers outside this package
	// (the CLI builds a plan without a Coordinator).
	DefaultFreshWithin = defaultFreshWithin
	// rollbackGrace bounds the rollback attempt when the rollout's own context is
	// already cancelled (operator abort, controller shutdown). Without it a
	// cancelled rollout would skip the rollback and leave a node on a broken binary.
	rollbackGrace = 60 * time.Second
)

func (c Config) withDefaults() Config {
	if c.ConfirmTimeout <= 0 {
		c.ConfirmTimeout = defaultConfirmTimeout
	}
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.FreshWithin <= 0 {
		c.FreshWithin = defaultFreshWithin
	}
	if c.LockPath == "" {
		c.LockPath = DefaultLockPath
	}
	return c
}

// ErrBusy is returned when a rollout is already running. Exactly one runs
// fleet-wide: two concurrent rollouts could take down two exits at once, which is
// the one outcome the whole design exists to prevent.
var ErrBusy = errors.New("a rolling upgrade is already in progress")

// Coordinator runs at most one rolling upgrade at a time.
//
// Rollout state is held in memory, NOT in the store. A rollout is bound to the
// process running it: the SSH sessions, the goroutine, and the base context all
// die with the controller. Persisting it would outlive all three and show a later
// process a rollout marked "in progress" that nothing is driving — a worse
// failure than losing the record, because an operator would wait on it. In-memory
// still satisfies the actual requirement: the UI polls over HTTP, so a page
// reload (or a second browser) reads the same live state.
type Coordinator struct {
	up   Upgrader
	read NodeReader
	cfg  Config
	log  *slog.Logger

	// now/sleep are injected so tests drive the gate on a virtual clock instead of
	// waiting out real timeouts.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	state  State
	cancel context.CancelFunc
	// lock is the cross-process rollout lock, held for the whole run and released
	// in run()'s teardown. Guarded by mu like the rest of the run state.
	lock *procLock
}

// New builds a Coordinator.
func New(up Upgrader, read NodeReader, cfg Config, log *slog.Logger) *Coordinator {
	if log == nil {
		log = slog.Default()
	}
	return &Coordinator{
		up: up, read: read, cfg: cfg.withDefaults(), log: log,
		now:   time.Now,
		sleep: sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Snapshot returns a copy of the current rollout state.
func (c *Coordinator) Snapshot() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.Nodes = append([]NodeProgress(nil), c.state.Nodes...)
	s.Skipped = append([]Skipped(nil), c.state.Skipped...)
	return s
}

// Running reports whether a rollout is in flight.
func (c *Coordinator) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Active
}

// Start launches a rollout in the background and returns immediately. ErrBusy if
// one is already running. Pass the controller's base context so the rollout
// aborts on shutdown rather than writing to a closed store.
func (c *Coordinator) Start(ctx context.Context, plan Plan) error {
	if len(plan.Targets) == 0 {
		return fmt.Errorf("nothing to roll: no outdated exits")
	}

	c.mu.Lock()
	if c.state.Active {
		c.mu.Unlock()
		return ErrBusy
	}
	// Take the fleet-wide lock BEFORE marking ourselves active, so a refusal leaves
	// no half-started state behind.
	lockPath := c.cfg.LockPath
	if lockPath == "-" {
		lockPath = ""
	}
	lock, err := acquireLock(lockPath)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.lock = lock
	runCtx, cancel := context.WithCancel(ctx)
	nodes := make([]NodeProgress, 0, len(plan.Targets))
	for _, t := range plan.Targets {
		nodes = append(nodes, NodeProgress{Target: t, Phase: PhasePending})
	}
	c.state = State{
		Active: true, Want: plan.Want, StartedAt: c.now(),
		Nodes: nodes, Skipped: plan.Skipped, LastUpdate: c.now(),
	}
	c.cancel = cancel
	c.mu.Unlock()

	go c.run(runCtx)
	return nil
}

// Abort stops a running rollout. The node in flight is rolled back — mid-upgrade
// is exactly the state that must not be left behind — and the untouched remainder
// is marked skipped.
func (c *Coordinator) Abort() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Wait blocks until no rollout is running. Test/shutdown helper.
func (c *Coordinator) Wait() {
	for c.Running() {
		time.Sleep(time.Millisecond)
	}
}

// run walks the plan one node at a time, stopping at the first failure.
func (c *Coordinator) run(ctx context.Context) {
	defer func() {
		c.mu.Lock()
		c.state.Active = false
		c.state.EndedAt = c.now()
		c.state.LastUpdate = c.now()
		// Release the fleet-wide lock only once the run is genuinely over, so a
		// second process cannot start while this one is still mid-node.
		c.lock.release()
		c.lock = nil
		c.mu.Unlock()
	}()

	for i := range c.snapshotLen() {
		if err := ctx.Err(); err != nil {
			c.markAborted("aborted before " + c.nodeID(i))
			c.skipFrom(i)
			return
		}
		if err := c.runNode(ctx, i); err != nil {
			// Abort the whole rollout on the first failure. The node has already been
			// rolled back by runNode; everything after it stays untouched, because the
			// most likely explanation for one node failing on this binary is that every
			// node will — and one broken exit must never become five.
			c.log.Error("rolling upgrade halted", "node", c.nodeID(i), "err", err)
			c.mu.Lock()
			c.state.Err = fmt.Sprintf("halted at %s: %v", c.state.Nodes[i].Name, err)
			c.mu.Unlock()
			c.skipFrom(i + 1)
			return
		}
	}
	c.log.Info("rolling upgrade complete", "nodes", c.snapshotLen())
}

// runNode upgrades one node and blocks until it proves it came back, or rolls it
// back. The returned error halts the rollout.
func (c *Coordinator) runNode(ctx context.Context, i int) error {
	id := c.nodeID(i)
	c.setPhase(i, PhaseUploading, func(n *NodeProgress) { n.StartedAt = c.now() })

	// Where the node stands BEFORE it is touched sets the bar it has to clear
	// afterwards. Read here, not at plan time: the plan may be minutes old, and it
	// is this moment's state the gate has to be fair to. Unreadable ⇒ demand Ready,
	// the strict default.
	before := domain.StateReady
	if n, err := c.read.GetNode(ctx, id); err == nil {
		before = n.State
	}

	// One call covers upload + sha256 verification + restart (the verification
	// happens inside, before the restart). The phases are reported around it so the
	// UI shows movement; the boundary between them is not separately observable.
	c.setPhase(i, PhaseVerifying, nil)
	installed, err := c.up.UpgradeAgentVerified(ctx, id)
	if err != nil {
		return c.fail(ctx, i, fmt.Errorf("upgrade: %w", err))
	}
	c.setPhase(i, PhaseRestarting, func(n *NodeProgress) { n.Installed = installed })

	// The gate: the node must come back Ready, ON THE VERSION WE JUST INSTALLED,
	// and reporting freshly. Anchoring on a version probed off the node itself is
	// what makes this a proof rather than a guess — a node that never restarts, or
	// that crash-loops back onto its old binary, keeps reporting the old version and
	// never satisfies it, no matter how long we wait.
	restartedAt := c.now()
	c.setPhase(i, PhaseConfirming, nil)
	if err := c.confirm(ctx, id, installed, restartedAt, before); err != nil {
		return c.fail(ctx, i, err)
	}

	c.setPhase(i, PhaseDone, func(n *NodeProgress) { n.EndedAt = c.now() })
	c.log.Info("node upgraded and confirmed", "node", id, "version", installed)
	return nil
}

// confirm blocks until the node satisfies the gate or the timeout expires.
func (c *Coordinator) confirm(ctx context.Context, id, want string, restartedAt time.Time, before domain.NodeState) error {
	deadline := restartedAt.Add(c.cfg.ConfirmTimeout)
	var last string
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("aborted while confirming %s: %w", id, err)
		}
		n, err := c.read.GetNode(ctx, id)
		switch {
		case err != nil:
			last = "store read failed: " + err.Error()
		default:
			last = c.gateReasonFrom(before, n, want, restartedAt)
			if last == "" {
				return nil
			}
		}
		if !c.now().Before(deadline) {
			return fmt.Errorf("node did not come back within %s (%s)", c.cfg.ConfirmTimeout, last)
		}
		if err := c.sleep(ctx, c.cfg.PollInterval); err != nil {
			return fmt.Errorf("aborted while confirming %s: %w", id, err)
		}
	}
}

// gateReason returns "" when the node satisfies the gate, else why it does not.
// All three conditions are load-bearing: Ready alone can be stale state left by
// the previous binary, a matching version alone does not mean the reconcile is
// healthy, and a LastSeen that predates the restart is the old process's.
//
// The conditions themselves live on domain.Node, because three other paths upgrade
// an agent and none of them used to ask this question at all.
func (c *Coordinator) gateReason(n domain.Node, want string, restartedAt time.Time) string {
	return c.gateReasonFrom(domain.StateReady, n, want, restartedAt)
}

// gateReasonFrom is gateReason with the bar set by the node's state before the
// upgrade; see domain.Node.AgentBackReasonFrom.
func (c *Coordinator) gateReasonFrom(before domain.NodeState, n domain.Node, want string, restartedAt time.Time) string {
	return n.AgentBackReasonFrom(before, want, restartedAt, c.now(), c.cfg.FreshWithin)
}

// nodeUntouched reports whether err says the upgrade failed BEFORE it modified
// anything on the node — no upload, no rollback snapshot taken in this attempt,
// no restart. It is a behavioural check rather than a sentinel comparison so the
// coordinator keeps depending on nothing but its own interfaces: whoever
// implements Upgrader decides how to signal it.
func nodeUntouched(err error) bool {
	var u interface{ NodeUntouched() bool }
	return errors.As(err, &u) && u.NodeUntouched()
}

// fail records the node's failure and, when the upgrade actually displaced
// something, rolls it back. The rollback runs on a detached, bounded context: the
// common failure modes (operator abort, controller shutdown) cancel the rollout's
// context, and a rollback that skipped itself because of that would leave the node
// on the binary that just failed.
//
// It is skipped entirely when the upgrade never reached the node. "It failed, so
// roll it back" only holds when there was something to roll back — and .prev is
// not a general-purpose escape hatch, it is whatever some EARLIER upgrade
// displaced. Restoring it after a dial timeout downgrades a node that was
// perfectly healthy, which is exactly what happened to pn8 on 2026-08-18: an SSH
// dial timed out, the rollback restored a week-old snapshot, and a node running
// wire 6 came back on wire 5. The failure still halts the rollout — only the
// pointless mutation is dropped.
func (c *Coordinator) fail(ctx context.Context, i int, cause error) error {
	id := c.nodeID(i)
	c.setPhase(i, PhaseFailed, func(n *NodeProgress) {
		n.Err = cause.Error()
		n.EndedAt = c.now()
	})
	if nodeUntouched(cause) {
		c.log.Error("node failed before the upgrade touched it; NOT rolling back", "node", id, "err", cause)
		return cause
	}
	c.log.Error("node failed its upgrade gate; rolling back", "node", id, "err", cause)

	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackGrace)
	defer cancel()
	if err := c.up.RollbackAgent(rbCtx, id); err != nil {
		c.setPhase(i, PhaseFailed, func(n *NodeProgress) {
			n.Err = fmt.Sprintf("%v; ROLLBACK ALSO FAILED: %v", cause, err)
		})
		c.log.Error("rollback failed — node needs manual recovery", "node", id, "err", err)
		return fmt.Errorf("%w (rollback failed: %v)", cause, err)
	}
	c.setPhase(i, PhaseRolledBack, func(n *NodeProgress) {
		n.RolledBack = true
		n.Err = cause.Error()
		n.EndedAt = c.now()
	})
	return cause
}

// skipFrom marks every not-yet-terminal node from i onward as skipped.
func (c *Coordinator) skipFrom(i int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for j := i; j < len(c.state.Nodes); j++ {
		if !c.state.Nodes[j].Phase.Terminal() {
			c.state.Nodes[j].Phase = PhaseSkipped
		}
	}
	c.state.LastUpdate = c.now()
}

func (c *Coordinator) markAborted(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Aborted = true
	if c.state.Err == "" {
		c.state.Err = reason
	}
	c.state.LastUpdate = c.now()
}

func (c *Coordinator) setPhase(i int, p Phase, mut func(*NodeProgress)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Nodes[i].Phase = p
	if mut != nil {
		mut(&c.state.Nodes[i])
	}
	c.state.LastUpdate = c.now()
}

func (c *Coordinator) nodeID(i int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Nodes[i].NodeID
}

func (c *Coordinator) snapshotLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.state.Nodes)
}
