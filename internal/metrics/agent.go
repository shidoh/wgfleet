package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/domain"
)

// AgentMetrics is the agent's own instrumentation, updated each reconcile pass
// and exposed on the agent's /metrics endpoint. Unlike the controller's
// store-projection, these are real counters/gauges the agent maintains.
type AgentMetrics struct {
	reconcileTotal    *prometheus.CounterVec // by result: success|error
	reconcileDuration prometheus.Histogram
	stateInfo         *prometheus.GaugeVec   // info metric: current state as a label
	checkUp           *prometheus.GaugeVec   // per self-check: 1 ok, 0 failing
	driftTotal        *prometheus.CounterVec // per component: drift repairs since start
	driftResources    prometheus.Gauge       // components repaired in the last pass
	egressReach       *prometheus.GaugeVec   // info: current egress reachability as a label
	egressActive      *prometheus.GaugeVec   // info: currently active egress method as a label
	egressThroughput  prometheus.Gauge       // last measured egress throughput, bytes/sec
	startTime         prometheus.Gauge

	node string
	role domain.Role
}

// NewAgentMetrics builds and registers the agent metrics on reg, labelled with
// the node identity. now is used to stamp the process start time.
func NewAgentMetrics(reg *prometheus.Registry, node string, role domain.Role, now time.Time) *AgentMetrics {
	m := &AgentMetrics{
		node: node,
		role: role,
		reconcileTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "agent", Name: "reconcile_total",
			Help: "Reconcile passes by result.",
		}, []string{"result"}),
		reconcileDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "agent", Name: "reconcile_duration_seconds",
			Help: "Duration of a reconcile pass.", Buckets: prometheus.DefBuckets,
		}),
		stateInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "state_info",
			Help: "Current node lifecycle state as a label; value is always 1.",
		}, []string{"state"}),
		checkUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "health_check",
			Help: "Result of a self-check: 1 ok, 0 failing.",
		}, []string{"check"}),
		driftTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "agent", Name: "drift_total",
			Help: "Components repaired after convergence (config drift), by component.",
		}, []string{"component"}),
		driftResources: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "drift_resources",
			Help: "Components that drifted and were repaired in the last reconcile pass.",
		}),
		egressReach: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "egress_reachability",
			Help: "Current egress reachability classification as a label (ok|degraded|blocked); value is always 1. 'blocked' is the censorship-block signal.",
		}, []string{"state"}),
		egressActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "egress_active",
			Help: "Currently active egress method as a label (warp|direct|...); value is always 1. Differs from the preferred egress while failed over (ADR-0017).",
		}, []string{"method"}),
		egressThroughput: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "egress_throughput_bytes",
			Help: "Last measured egress throughput in bytes/sec (ADR-0021). A sustained collapse below the configured floor auto-suspends the exit from the LB.",
		}),
		startTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "start_time_seconds",
			Help: "Unix time the agent process started.",
		}),
	}
	m.startTime.Set(float64(now.Unix()))
	reg.MustRegister(m.reconcileTotal, m.reconcileDuration, m.stateInfo, m.checkUp,
		m.driftTotal, m.driftResources, m.egressReach, m.egressActive, m.egressThroughput, m.startTime)
	return m
}

// ObserveReconcile records the outcome of one reconcile pass: duration, result,
// the derived state, and per-check results.
func (m *AgentMetrics) ObserveReconcile(d time.Duration, state domain.NodeState, checks []domain.HealthCheck, reconcileErr error) {
	m.reconcileDuration.Observe(d.Seconds())
	if reconcileErr != nil {
		m.reconcileTotal.WithLabelValues("error").Inc()
	} else {
		m.reconcileTotal.WithLabelValues("success").Inc()
	}

	// state_info is single-valued: reset then set the current state to 1.
	m.stateInfo.Reset()
	m.stateInfo.WithLabelValues(string(state)).Set(1)

	for _, c := range checks {
		m.checkUp.WithLabelValues(c.Name).Set(boolToFloat(c.OK))
	}
}

// ObserveEgress records the current egress reachability classification as a
// single-valued info gauge (ok|degraded|blocked). A no-op for the empty class
// (egress not WARP / nothing classified).
func (m *AgentMetrics) ObserveEgress(reach domain.EgressReachability) {
	if reach == "" {
		return
	}
	m.egressReach.Reset()
	m.egressReach.WithLabelValues(string(reach)).Set(1)
}

// ObserveEgressActive records the currently active egress method as a
// single-valued info gauge. A no-op for the empty method.
func (m *AgentMetrics) ObserveEgressActive(method domain.EgressMethod) {
	if method == "" {
		return
	}
	m.egressActive.Reset()
	m.egressActive.WithLabelValues(string(method)).Set(1)
}

// ObserveEgressThroughput records the last measured egress throughput (bytes/sec).
func (m *AgentMetrics) ObserveEgressThroughput(bytesPerSec float64) {
	m.egressThroughput.Set(bytesPerSec)
}

// ObserveDrift records that, on an unchanged desired spec, the named components
// had diverged and were repaired — i.e. real config drift, as opposed to a spec
// change the agent is rolling out. Call with the components changed on a pass
// whose spec matched the previous applied pass; pass nil/empty for no drift.
func (m *AgentMetrics) ObserveDrift(components []string) {
	m.driftResources.Set(float64(len(components)))
	for _, c := range components {
		m.driftTotal.WithLabelValues(c).Inc()
	}
}
