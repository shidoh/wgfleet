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
	transportActive   *prometheus.GaugeVec   // info: active master↔exit transport as a label (ADR-0025)
	egressThroughput  prometheus.Gauge       // last measured egress throughput, bytes/sec
	reconcileChanges  prometheus.Gauge       // resources changed in the last pass
	checkLatency      *prometheus.GaugeVec   // per self-check: probe latency, seconds
	startTime         prometheus.Gauge

	node string
	role domain.Role
}

// NewAgentMetrics builds and registers the agent metrics on reg. Every series
// carries the node + role as constant labels, so a Prometheus that scrapes each
// node's /metrics over its ZT address still groups cleanly by node in dashboards
// (no reliance on the instance address). now stamps the process start time.
func NewAgentMetrics(reg *prometheus.Registry, node string, role domain.Role, now time.Time) *AgentMetrics {
	cl := prometheus.Labels{"node": node, "role": string(role)}
	m := &AgentMetrics{
		node: node,
		role: role,
		reconcileTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "agent", Name: "reconcile_total",
			Help: "Reconcile passes by result.", ConstLabels: cl,
		}, []string{"result"}),
		reconcileDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "agent", Name: "reconcile_duration_seconds",
			Help: "Duration of a reconcile pass.", Buckets: prometheus.DefBuckets, ConstLabels: cl,
		}),
		stateInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "state_info",
			Help: "Current node lifecycle state as a label; value is always 1.", ConstLabels: cl,
		}, []string{"state"}),
		checkUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "health_check",
			Help: "Result of a self-check: 1 ok, 0 failing.", ConstLabels: cl,
		}, []string{"check"}),
		checkLatency: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "health_check_latency_seconds",
			Help: "Latency of a self-check's probe in seconds (e.g. egress RTT, DNS resolve).", ConstLabels: cl,
		}, []string{"check"}),
		driftTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "agent", Name: "drift_total",
			Help: "Components repaired after convergence (config drift), by component.", ConstLabels: cl,
		}, []string{"component"}),
		driftResources: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "drift_resources",
			Help: "Components that drifted and were repaired in the last reconcile pass.", ConstLabels: cl,
		}),
		reconcileChanges: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "reconcile_changes",
			Help: "Resources changed in the last reconcile pass (0 on a steady, fully-converged node).", ConstLabels: cl,
		}),
		egressReach: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "egress_reachability",
			Help: "Current egress reachability classification as a label (ok|degraded|blocked); value is always 1. 'blocked' is the censorship-block signal.", ConstLabels: cl,
		}, []string{"state"}),
		egressActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "egress_active",
			Help: "Currently active egress method as a label (warp|direct|...); value is always 1. Differs from the preferred egress while failed over (ADR-0017).", ConstLabels: cl,
		}, []string{"method"}),
		egressThroughput: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "egress_throughput_bytes",
			Help: "Last measured egress throughput in bytes/sec (ADR-0021). A sustained collapse below the configured floor auto-suspends the exit from the LB.", ConstLabels: cl,
		}),
		startTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "start_time_seconds",
			Help: "Unix time the agent process started.", ConstLabels: cl,
		}),
	}
	// transport_active is exit-only (the active master↔exit transport, ADR-0025).
	// Registering it on a master would expose an empty series, so absent()-based
	// alerts fire on masters that have no transport at all; gate it on the role.
	if role == domain.RoleExit {
		m.transportActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "transport_active",
			Help: "Active master↔exit transport as a label (awg|reality-xhttp); value is always 1 (ADR-0025). Exit nodes only.", ConstLabels: cl,
		}, []string{"transport"})
	}

	m.startTime.Set(float64(now.Unix()))
	// Create both children up front. A CounterVec materialises a child only on its
	// first WithLabelValues, so an agent that has never had a SUCCESSFUL pass since it
	// started exposes result="error" alone — and WgfleetReconcileErrors is written as
	// `increase(...{result!="success"}) > N and ignoring(result) increase(...{result="success"}) == 0`,
	// which needs both sides to exist. Without this the alert is not quieter but DEAD
	// in the case it was written for: an agent restarted by an upgrade or a reboot
	// that then cannot converge at all.
	m.reconcileTotal.WithLabelValues("success")
	m.reconcileTotal.WithLabelValues("error")

	reg.MustRegister(m.reconcileTotal, m.reconcileDuration, m.stateInfo, m.checkUp, m.checkLatency,
		m.driftTotal, m.driftResources, m.reconcileChanges, m.egressReach, m.egressActive,
		m.egressThroughput, m.startTime)
	if m.transportActive != nil {
		reg.MustRegister(m.transportActive)
	}
	return m
}

// ObserveReconcile records the outcome of one reconcile pass: duration, the number
// of resources changed, result, the derived state, and per-check results + latency.
func (m *AgentMetrics) ObserveReconcile(d time.Duration, changes int, state domain.NodeState, checks []domain.HealthCheck, reconcileErr error) {
	m.reconcileDuration.Observe(d.Seconds())
	m.reconcileChanges.Set(float64(changes))
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
		if c.Latency > 0 {
			m.checkLatency.WithLabelValues(c.Name).Set(c.Latency.Seconds())
		}
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

// ObserveTransport records the exit's active master↔exit transport as a
// single-valued info gauge (ADR-0025). A no-op for the empty transport.
func (m *AgentMetrics) ObserveTransport(t domain.MasterTransport) {
	// transportActive is nil on non-exit roles (never registered), so guard it —
	// a master must never touch this exit-only series.
	if t == "" || m.transportActive == nil {
		return
	}
	m.transportActive.Reset()
	m.transportActive.WithLabelValues(string(t)).Set(1)
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
