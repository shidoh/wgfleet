package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// NewCAExpiryCollector publishes when the fleet CA expires.
//
// The CA is issued for ten years and its NotAfter was written once and never read
// back, so the one certificate whose lapse cannot be repaired over the control
// plane was the one nothing watched. When it goes, every node's client certificate
// becomes untrusted at the same moment — there is no rolling failure to notice
// first, and no channel left to fix it through.
//
// notAfter is read once: a CA does not rotate under a running controller, and
// re-parsing it on every scrape would only add a file read that can fail.
func NewCAExpiryCollector(reg *prometheus.Registry, notAfter time.Time) {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "controller",
		Name:      "ca_expiry_timestamp_seconds",
		Help:      "Unix time at which the fleet CA expires. Every node certificate chains to it, so its lapse invalidates the whole fleet at once and cannot be repaired over the control plane.",
	})
	g.Set(float64(notAfter.Unix()))
	reg.MustRegister(g)
}
