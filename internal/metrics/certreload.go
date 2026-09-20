package metrics

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// certReloadFailures counts handshakes that could not re-read this node's
// certificate/key pair from disk.
//
// Package-level, and published by a collector rather than incremented through
// AgentMetrics, because of WHEN the fact happens: the mTLS config is built before
// the metrics registry exists, and a reload can fail from that moment on. The
// first version handed the count to the agent to drain once per reconcile pass —
// and that drain went in beside a master-only observation, inside its role gate,
// so on every exit in the fleet the counter accumulated in memory and was
// published as zero forever. A call site that can be put in the wrong branch is a
// call site that eventually is; there is no longer one to misplace.
var certReloadFailures atomic.Int64

// RecordCertReloadError is called from the TLS layer when a handshake could not
// re-read the pair from disk and fell back to the last one that loaded. Safe from
// any goroutine and at any time, including before any registry exists.
func RecordCertReloadError() { certReloadFailures.Add(1) }

type certReloadCollector struct{ desc *prometheus.Desc }

var _ prometheus.Collector = (*certReloadCollector)(nil)

func newCertReloadCollector(labels prometheus.Labels) *certReloadCollector {
	return &certReloadCollector{desc: prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "agent", "cert_reload_errors_total"),
		"Handshakes at which this node's certificate/key pair could not be re-read from disk. The handshake still proceeds on the last pair that loaded, so the node keeps authenticating and looks healthy while the pair on disk is one the next restart cannot load at all.",
		nil, labels,
	)}
}

func (c *certReloadCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *certReloadCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(certReloadFailures.Load()))
}
