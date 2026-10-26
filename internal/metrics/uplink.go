package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// uplinkCounterPrefix marks the nft counters that count the master's own TCP
// handshakes rather than drops (rendered by netfw on a master's public address).
const uplinkCounterPrefix = "uplink_"

// UplinkMetrics is the master's measurement of its own uplink: TCP connects to the
// other masters (internal/agent/uplink).
type UplinkMetrics struct {
	probes  *prometheus.CounterVec
	connect *prometheus.HistogramVec
}

// NewUplinkMetrics registers the uplink series on reg with node + role as
// constant labels, like the rest of the agent's metrics.
func NewUplinkMetrics(reg *prometheus.Registry, node, role string) *UplinkMetrics {
	cl := prometheus.Labels{"node": node, "role": role}
	m := &UplinkMetrics{
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "agent", Name: "uplink_probes_total",
			Help:        "TCP connects from this master to another master's world-open port, by result: ok, slow (a retransmitted SYN, over 0.9 s), refused (a reset in answer) or fail (no answer).",
			ConstLabels: cl,
		}, []string{"peer", "result"}),
		connect: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "agent", Name: "uplink_connect_seconds",
			Help:        "Connect time of the successful uplink probes. Over 0.9 s is a retransmitted SYN.",
			ConstLabels: cl,
			Buckets:     []float64{0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 0.9, 1.5, 2.5, 3.5},
		}, []string{"peer"}),
	}
	reg.MustRegister(m.probes, m.connect)
	return m
}

// ObserveUplinkProbe records one probe. A failure has no connect time to record.
// Nil-safe, like the agent's other recorders, so a node with /metrics off probes
// into nothing.
func (m *UplinkMetrics) ObserveUplinkProbe(peer, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.probes.WithLabelValues(peer, result).Inc()
	if result == "ok" || result == "slow" {
		m.connect.WithLabelValues(peer).Observe(d.Seconds())
	}
}
