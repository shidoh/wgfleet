package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
	"github.com/shidoh/wgfleet/internal/controller/provmgr"
	"github.com/shidoh/wgfleet/internal/controller/rollout"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/version"
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

	// The selection target is the controller's own build: the Makefile stamps both
	// binaries from the same tree, so "outdated" means "not the build I am". The
	// per-node gate does not rely on this — it uses the version probed off each
	// node after upload — so an operator pushing a binary built elsewhere still
	// gets a correct gate.
	rp := rollout.BuildPlan(cfg.Fleet, nodes, version.Short())
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

// webRoller adapts the coordinator to the dashboard's Roller port: the UI knows
// only "plan / start / abort / observe", while resolving the plan (store
// inventory + fleet manifest + this build's version) stays here.
type webRoller struct {
	co    *rollout.Coordinator
	st    store.Store
	fleet config.FleetSection
	ctx   context.Context // controller base context; rollouts abort on shutdown
	log   *slog.Logger
}

func (w *webRoller) Plan() rollout.Plan {
	nodes, err := w.st.ListNodes(w.ctx)
	if err != nil {
		// Surface as an empty plan (the panel then offers nothing to roll) and log —
		// a dashboard poll must not take the page down over a transient store error.
		w.log.Warn("rollout plan: list nodes failed", "err", err)
		return rollout.Plan{Want: version.Short()}
	}
	return rollout.BuildPlan(w.fleet, nodes, version.Short())
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
