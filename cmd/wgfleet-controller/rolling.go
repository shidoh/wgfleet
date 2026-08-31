package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provisioner"
	"github.com/shidoh/wgfleet/internal/controller/provmgr"
	"github.com/shidoh/wgfleet/internal/controller/rollout"
	"github.com/shidoh/wgfleet/internal/controller/store"
)

// rollingUpgrade drives a fleet-wide rolling agent upgrade from the CLI.
// Progress streams to stdout so it is usable from a script; --plan prints the
// ordered plan and touches nothing.
//
// It builds its OWN provmgr.Manager and rollout.Coordinator — this is a separate
// process from the serving controller, so it shares none of that process's memory.
// An earlier version of this comment claimed it ran "over the same coordinator the
// Web UI action uses"; that was never true, and because both the coordinator's
// Active flag and provmgr's per-node inflight map are plain in-memory state,
// nothing stopped a CLI run and a UI run from picking the same exit and driving
// its upload/verify/restart concurrently — or, on failure, each rolling back the
// other's work and flapping that node's agent. Fleet-wide exclusion now comes from
// an flock (internal/controller/rollout/lock.go), which the kernel releases if the
// holder dies; a second rollout is refused with ErrLockHeld rather than queued.
//
// It may run alongside a serving controller: it opens the store like --provision
// does (sqlite WAL tolerates the concurrent open), and it only ever touches
// exits, never the co-located master this controller runs on. The controller
// MUST be up for a rollout to confirm anything — the gate reads the node state
// that the serving controller writes from agent check-ins.
func rollingUpgrade(cfg *config.ControllerConfig, ca *pki.CA, agentBin string, plan bool) error {
	if agentBin == "" {
		agentBin = cfg.Controller.AgentBin
	}
	if agentBin == "" {
		return fmt.Errorf("no agent binary: pass --agent-bin or set controller.agent_bin")
	}
	// The comment above says the controller MUST be up, and nothing checked it. With
	// it stopped, node 1 is uploaded and restarted, fails the come-back gate for its
	// full timeout because no controller is there to record the check-in, and is then
	// ROLLED BACK to whatever .prev holds — a downgrade of a healthy node caused by
	// nothing but the order the operator started things in. A plan changes nothing,
	// so it stays allowed.
	if !plan && cfg.Controller.Listen != "" && !controllerIsLive(cfg.Controller.Listen) {
		return fmt.Errorf("no controller is serving on %s: a rollout confirms each node "+
			"from the state a running controller records, so every node would fail its "+
			"come-back gate and be rolled back — start the controller first",
			cfg.Controller.Listen)
	}

	st, err := store.Open(cfg.Controller.Store)
	if err != nil {
		return fmt.Errorf("open store %q: %w", cfg.Controller.Store, err)
	}
	defer func() { _ = st.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	nodes, err := st.ListNodes(ctx)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}

	// The selection target is the version of the binary about to be pushed — NOT
	// this controller's own build. Those match only when both binaries were
	// deployed from the same tree; deploy just one and selecting on the
	// controller's version marks every node outdated forever while each rollout
	// reinstalls the version the node already had, reporting success every time.
	want, err := provisioner.ProbeLocalAgentVersion(ctx, agentBin)
	if err != nil {
		return fmt.Errorf("identify agent binary %s: %w", agentBin, err)
	}
	rp := rollout.BuildPlan(cfg.Fleet, nodes, want, time.Now(), rollout.DefaultFreshWithin)
	printRollingPlan(rp, agentBin)
	if plan {
		return nil
	}
	if rp.Outdated() == 0 {
		return nil
	}

	mgr := provmgr.New(st, ca, cfg.Fleet, provmgr.Options{AgentBinPath: agentBin}, slog.Default())
	mgr.SetBaseContext(ctx)
	defer mgr.Wait()

	co := rollout.New(mgr, st, rollout.Config{}, slog.Default())
	if err := co.Start(ctx, rp); err != nil {
		return err
	}
	return streamRollout(ctx, co)
}

// agentBinVersion resolves — and caches — the version identity of the agent
// binary a rollout would push.
//
// Cached because the dashboard polls the rollout panel every 2-15s and every
// open tab polls independently; re-execing a 28 MB binary on each poll is pure
// waste. The cache key is the file's size and mtime, so redeploying the binary
// under a running controller invalidates it without a restart.
type agentBinVersion struct {
	path string

	mu  sync.Mutex
	key string // size+mtime of the probed file
	ver string
	err error
}

func (c *agentBinVersion) get(ctx context.Context) (string, error) {
	if c.path == "" {
		return "", fmt.Errorf("no agent binary configured (controller.agent_bin)")
	}
	fi, err := os.Stat(c.path)
	if err != nil {
		return "", fmt.Errorf("stat agent binary: %w", err)
	}
	key := fmt.Sprintf("%d/%d", fi.Size(), fi.ModTime().UnixNano())

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == key {
		return c.ver, c.err
	}
	ver, err := provisioner.ProbeLocalAgentVersion(ctx, c.path)
	c.key, c.ver, c.err = key, ver, err
	return ver, err
}

// webRoller adapts the coordinator to the dashboard's Roller port: the UI knows
// only "plan / start / abort / observe", while resolving the plan (store
// inventory + fleet manifest + the pushed binary's version) stays here.
type webRoller struct {
	co     *rollout.Coordinator
	st     store.Store
	fleet  config.FleetSection
	binVer *agentBinVersion
	ctx    context.Context // controller base context; rollouts abort on shutdown
	log    *slog.Logger
}

func (w *webRoller) Plan() rollout.Plan {
	// Select against the binary that will actually be pushed, never this
	// controller's own build. The two are the same tree only when both binaries
	// were deployed together; deploy just one and selecting on the controller's
	// version makes every node permanently "outdated" while each rollout
	// dutifully reinstalls the version the node already had.
	want, err := w.binVer.get(w.ctx)
	if err != nil {
		w.log.Warn("rollout plan: cannot identify the agent binary", "err", err)
		return rollout.Plan{Unavailable: err.Error()}
	}
	nodes, err := w.st.ListNodes(w.ctx)
	if err != nil {
		// Surface as an empty plan (the panel then offers nothing to roll) and log —
		// a dashboard poll must not take the page down over a transient store error.
		w.log.Warn("rollout plan: list nodes failed", "err", err)
		return rollout.Plan{Want: want}
	}
	return rollout.BuildPlan(w.fleet, nodes, want, time.Now(), rollout.DefaultFreshWithin)
}

func (w *webRoller) Start() error            { return w.co.Start(w.ctx, w.Plan()) }
func (w *webRoller) Abort()                  { w.co.Abort() }
func (w *webRoller) Snapshot() rollout.State { return w.co.Snapshot() }

func printRollingPlan(rp rollout.Plan, agentBin string) {
	fmt.Printf("rolling agent upgrade — binary %s, target %s\n", agentBin, rp.Want)
	if rp.Outdated() == 0 {
		fmt.Println("\nnothing to do: every exit is already on this build.")
	}
	for i, t := range rp.Targets {
		cur := t.Current
		if cur == "" {
			cur = "(never reported)"
		}
		fmt.Printf("  %d. %-12s [%s]  %s → %s\n", i+1, t.Name, t.Tier, cur, rp.Want)
	}
	for _, s := range rp.Skipped {
		fmt.Printf("     %-12s skipped: %s\n", s.Name, s.Reason)
	}
	fmt.Println("\nmasters are excluded: the master is co-located with this controller.")
}

// streamRollout prints each node's phase transitions until the rollout ends,
// then reports the outcome. It polls the coordinator's snapshot rather than
// subscribing, matching how the Web UI observes the same state.
func streamRollout(ctx context.Context, co *rollout.Coordinator) error {
	seen := map[string]rollout.Phase{}
	aborting := false
	for {
		s := co.Snapshot()
		for _, n := range s.Nodes {
			if seen[n.Name] == n.Phase {
				continue
			}
			seen[n.Name] = n.Phase
			line := fmt.Sprintf("[%s] %-12s %s", time.Now().Format("15:04:05"), n.Name, n.Phase)
			if n.Installed != "" && n.Phase == rollout.PhaseDone {
				line += " (" + n.Installed + ")"
			}
			if n.Err != "" {
				line += " — " + n.Err
			}
			fmt.Println(line)
		}
		if !s.Active {
			fmt.Printf("\n%d/%d node(s) upgraded\n", s.Done(), s.Total())
			if s.Err != "" {
				return fmt.Errorf("rolling upgrade halted: %s", s.Err)
			}
			return nil
		}
		// On SIGINT ask the coordinator to unwind (it rolls back the node in flight)
		// and keep streaming until it does, rather than exiting mid-upgrade. Latch it:
		// a cancelled ctx.Done() is permanently ready, so selecting on it again would
		// spin instead of polling.
		if !aborting && ctx.Err() != nil {
			aborting = true
			fmt.Println("\ninterrupted — rolling back the node in flight, please wait…")
			co.Abort()
		}
		time.Sleep(500 * time.Millisecond)
	}
}
