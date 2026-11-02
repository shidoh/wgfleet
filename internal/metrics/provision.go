package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// ProvisionMetrics instruments the controller's SSH bootstrap pipeline: how long
// a node took to provision and whether it succeeded. It is the control-plane
// counterpart to the agent's reconcile_duration histogram, and is
// recorded around provmgr.Provision (the same path the CLI --provision and the
// Web UI button drive).
type ProvisionMetrics struct {
	duration *prometheus.HistogramVec // by role + result: success|error
}

// provisionBuckets spans the realistic range of a node bootstrap. A first apply
// pulls container images and registers WARP over SSH, so it can take minutes;
// the upper buckets capture that without losing resolution on fast plan/retry
// runs.
var provisionBuckets = []float64{1, 5, 15, 30, 60, 120, 300, 600, 900}

// NewProvisionMetrics builds and registers the provisioning histogram on reg.
func NewProvisionMetrics(reg *prometheus.Registry) *ProvisionMetrics {
	m := &ProvisionMetrics{
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "provision", Name: "duration_seconds",
			Help:    "Duration of an SSH bootstrap (apply) of a fleet node, by role and result.",
			Buckets: provisionBuckets,
		}, []string{"role", "result"}),
	}
	reg.MustRegister(m.duration)
	return m
}

// ObserveProvision records one provisioning run's wall-clock duration, labelled
// by node role and result (success when err is nil, else error). A nil receiver
// is a no-op so provmgr can run without metrics wired (CLI/tests).
func (m *ProvisionMetrics) ObserveProvision(role string, seconds float64, err error) {
	if m == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.duration.WithLabelValues(role, result).Observe(seconds)
}
