// Package health runs an agent's self-checks after a reconcile and aggregates
// them into a node lifecycle state. A
// node is Ready only when every check passes; a failing check makes it Degraded;
// a failed reconcile makes it Error. The checks themselves are role-specific
// (exit: WG handshake freshness, WARP egress, DNS; master: mihomo API) and their
// probes are injectable so the aggregation logic is testable without a live node.
package health

import (
	"context"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Result is the outcome of one probe.
type Result struct {
	OK      bool
	Detail  string
	Latency time.Duration
}

// Probe performs a single self-check.
type Probe func(ctx context.Context) Result

// Check is a named self-check.
type Check struct {
	Name  string
	Probe Probe
}

// Evaluate runs every check and aggregates the results into a node state plus
// per-check details suitable for a status report.
//
//   - reconcileErr != nil ⇒ Error (with a synthetic "reconcile" check), checks
//     are NOT run (the node isn't in a state worth probing).
//   - all checks OK ⇒ Ready.
//   - at least one check fails ⇒ Degraded.
//   - no checks ⇒ Reconciling (nothing to assert Ready on yet).
func Evaluate(ctx context.Context, reconcileErr error, checks []Check) (domain.NodeState, []domain.HealthCheck) {
	if reconcileErr != nil {
		return domain.StateError, []domain.HealthCheck{{
			Name:   "reconcile",
			OK:     false,
			Detail: reconcileErr.Error(),
		}}
	}
	if len(checks) == 0 {
		return domain.StateReconciling, nil
	}

	results := make([]domain.HealthCheck, 0, len(checks))
	allOK := true
	for _, c := range checks {
		r := c.Probe(ctx)
		results = append(results, domain.HealthCheck{
			Name:    c.Name,
			OK:      r.OK,
			Detail:  r.Detail,
			Latency: r.Latency,
		})
		if !r.OK {
			allOK = false
		}
	}

	if allOK {
		return domain.StateReady, results
	}
	return domain.StateDegraded, results
}

// ok / fail are small helpers for building probe results.
func ok(detail string, latency time.Duration) Result {
	return Result{OK: true, Detail: detail, Latency: latency}
}

func fail(detail string) Result {
	return Result{OK: false, Detail: detail}
}
