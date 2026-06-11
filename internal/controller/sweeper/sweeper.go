// Package sweeper marks silent nodes Degraded. Agents report status on each
// reconcile; if one dies, its node would otherwise stay Ready/Reconciling
// forever. The sweeper runs on the controller and, on a tick, demotes any
// active node that has not reported within a staleness threshold — so the
// dashboard and metrics tell the truth about a dead agent. When the agent
// recovers it reports again and its status update restores the state.
package sweeper

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Sweeper demotes stale nodes. It owns no state beyond the store and config.
type Sweeper struct {
	store     store.Store
	threshold time.Duration
	now       func() time.Time
	log       *slog.Logger
}

// New builds a Sweeper. threshold must be > 0 (callers gate on that).
func New(st store.Store, threshold time.Duration, log *slog.Logger) *Sweeper {
	if log == nil {
		log = slog.Default()
	}
	return &Sweeper{store: st, threshold: threshold, now: time.Now, log: log}
}

// Run sweeps every interval until ctx is cancelled.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := s.Sweep(ctx); err != nil {
				s.log.Warn("staleness sweep failed", "err", err)
			} else if n > 0 {
				s.log.Info("staleness sweep demoted nodes", "count", n)
			}
		}
	}
}

// Sweep demotes every active node whose last contact is older than the
// threshold, and returns how many it changed. Only Ready and Reconciling nodes
// are eligible: Pending/Provisioning legitimately have no reports yet, and
// Error/Degraded are already non-healthy (re-stamping would just churn
// updated_at). Last contact is the node's LastSeen, or — if it has never
// reported — its UpdatedAt (so a node that registered and immediately died is
// caught too).
func (s *Sweeper) Sweep(ctx context.Context) (int, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return 0, fmt.Errorf("sweep: list nodes: %w", err)
	}
	now := s.now()
	changed := 0
	for _, n := range nodes {
		if !eligible(n.State) {
			continue
		}
		age := now.Sub(lastContact(n))
		if age <= s.threshold {
			continue
		}
		reason := fmt.Sprintf("no status report in %s", age.Round(time.Second))
		if err := s.store.SetNodeState(ctx, n.ID, domain.StateDegraded, reason); err != nil {
			s.log.Warn("sweep: demote failed", "node", n.ID, "err", err)
			continue
		}
		s.log.Info("node demoted to Degraded (stale)", "node", n.ID, "age", age.Round(time.Second))
		changed++
	}
	return changed, nil
}

func eligible(state domain.NodeState) bool {
	return state == domain.StateReady || state == domain.StateReconciling
}

func lastContact(n domain.Node) time.Time {
	if !n.LastSeen.IsZero() {
		return n.LastSeen
	}
	return n.UpdatedAt
}
