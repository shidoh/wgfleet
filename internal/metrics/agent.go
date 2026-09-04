package metrics

import (
	"strconv"
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
	// Exit-tier state, master-only (see the role gate in NewAgentMetrics). These
	// are the only record of WHY an exit is or is not carrying traffic: the
	// multi-destination verdict lives in the agent's memory, and mihomo's own view
	// (exported by the controller as wgfleet_exit_tunnel_*) shows the effect
	// without the cause.
	exitHeldOut      *prometheus.GaugeVec // per exit: 1 while our verdict holds it out of wg-best
	reserveTier      prometheus.Gauge     // 1 when wg-best routes to the reserve tier
	standbyUsable    prometheus.Gauge     // inactive tier: members the warm probe found usable
	standbyTotal     prometheus.Gauge     // inactive tier: members the warm probe could sample
	standbyTransport *prometheus.GaugeVec // per exit: is its INACTIVE transport usable
	egressThroughput prometheus.Gauge     // last measured egress throughput, bytes/sec
	udpReturnSocket  *prometheus.GaugeVec // per UDP port: can a TPROXY reply socket still be opened
	udpReturnKnown   *prometheus.GaugeVec // per UDP port: is a blocked port one we have decided about
	mihomoErrors     prometheus.Counter   // error lines mihomo wrote about itself
	clientPathOK     *prometheus.GaugeVec // per probe: does the client path work end to end
	reconcileChanges prometheus.Gauge     // resources changed in the last pass
	checkLatency     *prometheus.GaugeVec // per self-check: probe latency, seconds
	startTime        prometheus.Gauge

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
		udpReturnSocket: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "udp_return_socket",
			Help: "1 when a TPROXY reply socket can still be opened for this destination port; 0 when a socket this namespace already holds makes it impossible, so client traffic to that port gets no replies.", ConstLabels: cl,
		}, []string{"port"}),
		clientPathOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "client_path_ok",
			Help: "1 when the master's own client can send and receive over this protocol through the full client path (interface, firewall, proxy, exit); 0 when it cannot. The only signal that measures the sentence every component metric misses.", ConstLabels: cl,
		}, []string{"probe"}),
		mihomoErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "agent", Name: "mihomo_errors_total",
			Help: "Error lines mihomo has written about itself. Deliberately unclassified: the next failure of this kind will have a different message, and the signal is that the data plane is complaining at all.", ConstLabels: cl,
		}),
		udpReturnKnown: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "udp_return_known",
			Help: "1 when a port whose replies cannot come back is one we have decided about (refused by rule, or a declared loss); 0 marks a silent black hole.", ConstLabels: cl,
		}, []string{"port"}),
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
	// The tier series are the mirror image: only a master has a tier decision, and
	// registering them on every exit would leave empty series that absent()-based
	// rules read as a fleet-wide fault.
	if role == domain.RoleMaster {
		m.exitHeldOut = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "exit_held_out",
			Help: "1 while the master's multi-destination probe is holding this exit out of the wg-best rotation, else 0. Master nodes only.", ConstLabels: cl,
		}, []string{"exit"})
		m.reserveTier = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "reserve_tier_active",
			Help: "1 when wg-best routes to the reserve exit tier (ADR-0029), else 0. Master nodes only.", ConstLabels: cl,
		})
		m.standbyUsable = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "standby_tier_usable",
			Help: "Exits of the INACTIVE tier that the last warm probe found usable. Master nodes only.", ConstLabels: cl,
		})
		m.standbyTotal = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "standby_tier_total",
			Help: "Exits of the INACTIVE tier that the last warm probe could sample. 0 means the standby has not been measured — a failover would be blind. Master nodes only.", ConstLabels: cl,
		})
		m.standbyTransport = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "agent", Name: "standby_transport_usable",
			Help: "1 when the last probe found this exit's INACTIVE transport able to reach the internet, 0 when it could not. Absent means never measured, which is not the same as healthy. Master nodes only.", ConstLabels: cl,
		}, []string{"exit", "transport"})
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
		m.egressThroughput, m.startTime, m.udpReturnSocket, m.udpReturnKnown, m.mihomoErrors, m.clientPathOK)
	if m.transportActive != nil {
		reg.MustRegister(m.transportActive)
	}
	if m.exitHeldOut != nil {
		reg.MustRegister(m.exitHeldOut, m.reserveTier, m.standbyUsable, m.standbyTotal, m.standbyTransport)
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

// ObserveTier records the master's exit-tier state for this pass: which tier
// carries traffic, which of its exits our multi-destination verdict is holding
// out of the load balancer, and how the inactive tier looked to the last warm
// probe. A no-op on a non-master (the series are never registered there).
//
// rotation is REPLACED, not merged: an exit that left the active tier — drained,
// or the tier flipped — must stop reporting rather than freeze at its last value,
// because a stale 1 reads as an outage nothing will ever clear.
func (m *AgentMetrics) ObserveTier(reserveActive bool, rotation map[string]bool, standbyUsable, standbyTotal int) {
	if m.exitHeldOut == nil {
		return
	}
	m.exitHeldOut.Reset()
	for exit, held := range rotation {
		m.exitHeldOut.WithLabelValues(exit).Set(boolToFloat(held))
	}
	m.reserveTier.Set(boolToFloat(reserveActive))
	m.standbyUsable.Set(float64(standbyUsable))
	m.standbyTotal.Set(float64(standbyTotal))
}

// StandbyTransport identifies one exit's inactive transport — the path an
// operator would switch that exit onto (ADR-0025). The transport is a label
// because "vn0's standby is broken" and "which of the two is it" are the same
// question at 4am.
type StandbyTransport struct {
	Exit      string
	Transport string
}

// ObserveStandbyTransports records, per exit, whether its INACTIVE transport
// could reach the internet on the last probe. A no-op on a non-master.
//
// The set is REPLACED, not merged: an exit that stops having a standby — its
// second transport disabled, or the node drained — must leave the series rather
// than freeze at its last value, or a stale 0 pages forever about a fallback
// nobody is waiting on.
func (m *AgentMetrics) ObserveStandbyTransports(usable map[StandbyTransport]bool) {
	if m.standbyTransport == nil {
		return
	}
	m.standbyTransport.Reset()
	for t, ok := range usable {
		m.standbyTransport.WithLabelValues(t.Exit, t.Transport).Set(boolToFloat(ok))
	}
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

// ObserveUDPReturn records, per destination port, whether a TPROXY reply socket is
// still possible and whether a port that blocks one is a decision rather than an
// accident.
//
// It is the raw observation behind the udp-return-path check, and both series are
// needed: the check answers "is this safe", the metric answers "what is actually
// true". Without the second an operator cannot tell a black hole we have fixed
// from one that was never there, and the alert has nothing to compare against.
//
// Reset first: a port that no longer has a socket must stop being reported rather
// than freeze at its last value.
func (m *AgentMetrics) ObserveUDPReturn(bindable, known map[int]bool) {
	m.udpReturnSocket.Reset()
	m.udpReturnKnown.Reset()
	for port, ok := range bindable {
		label := strconv.Itoa(port)
		m.udpReturnSocket.WithLabelValues(label).Set(boolToFloat(ok))
		m.udpReturnKnown.WithLabelValues(label).Set(boolToFloat(known[port]))
	}
}

// ObserveMihomoErrors adds the error lines mihomo wrote since the last look.
//
// Unclassified on purpose. Alerting on a specific message ("listenLocalConn")
// catches only the failure already understood and fixed; the next one of this
// class will say something else. What generalises is that the data plane is
// complaining at all — 97787 lines over eight days with no metric is what let a
// dead protocol look healthy.
func (m *AgentMetrics) ObserveMihomoErrors(n int) {
	if n > 0 {
		m.mihomoErrors.Add(float64(n))
	}
}

// ObserveClientPath records, per probe, whether the master's own client could
// send and receive through the full client path.
//
// Reset first: a probe that stops being taken must stop being reported rather
// than freeze at its last value. A frozen green is exactly the shape of the
// failure this metric exists to catch — every other signal was green for eight
// days while client QUIC was dead, because each of them was measuring something
// that was genuinely fine.
func (m *AgentMetrics) ObserveClientPath(results map[string]bool) {
	m.clientPathOK.Reset()
	for probe, ok := range results {
		m.clientPathOK.WithLabelValues(probe).Set(boolToFloat(ok))
	}
}
