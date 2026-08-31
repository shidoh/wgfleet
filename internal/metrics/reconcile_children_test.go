package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/shidoh/wgfleet/internal/domain"
)

// WgfleetReconcileErrors is written as
//
//	increase(...{result!="success"}[30m]) > 5
//	  and ignoring(result) increase(...{result="success"}[30m]) == 0
//
// and `and` needs BOTH sides to have series. A CounterVec creates a child only when
// WithLabelValues is first called, so an agent that has never had a successful pass
// since it started exposes only result="error" — the right side is empty, the whole
// expression is empty, and the alert cannot fire. That is exactly the case it exists
// for: an agent restarted by an upgrade or a reboot that then cannot converge.
func TestReconcileCountersExistBeforeTheFirstPass(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Now())

	// gatherValue only reads gauges, so read the counter family directly.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "wgfleet_agent_reconcile_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "result" {
					seen[lp.GetValue()] = m.GetCounter().GetValue()
				}
			}
		}
	}
	for _, result := range []string{"success", "error"} {
		v, ok := seen[result]
		if !ok {
			t.Errorf("reconcile_total{result=%q} does not exist before the first pass — the alert that needs both sides is dead", result)
			continue
		}
		if v != 0 {
			t.Errorf("reconcile_total{result=%q} = %v, want a pre-initialised 0", result, v)
		}
	}
}
