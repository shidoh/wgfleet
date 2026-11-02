// Package metrics exposes Prometheus instrumentation for the controller and the
// agent. The controller's fleet view is a scrape-time projection
// of the state store (no counters to keep in sync); the agent reports its own
// reconcile/health counters. Both /metrics endpoints bind the mgmt/ZT address
// only, never the public interface.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace prefixes every wgfleet metric.
const namespace = "wgfleet"

// Handler returns an HTTP handler serving the given registry in the Prometheus
// text exposition format.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// NewRegistry returns a fresh registry with the Go runtime collector registered.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector())
	return reg
}
