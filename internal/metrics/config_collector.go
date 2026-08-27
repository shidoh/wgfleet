package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/config"
)

// ConfigCollector reports whether the manifest on disk still matches the one this
// controller is running on.
//
// A collector rather than a background ticker: the comparison is a file read and a
// hash, so doing it at scrape time costs nothing, needs no goroutine or shutdown
// path, and cannot drift out of date between ticks. The scrape interval IS the
// sample rate.
type ConfigCollector struct {
	path string
	eff  *config.Effective

	drift *prometheus.Desc
	info  *prometheus.Desc
}

// NewConfigCollector registers the drift metrics for the manifest at path.
func NewConfigCollector(reg *prometheus.Registry, path string, eff *config.Effective) *ConfigCollector {
	c := &ConfigCollector{
		path: path,
		eff:  eff,
		drift: prometheus.NewDesc(
			namespace+"_controller_config_drift",
			"1 when the manifest on disk differs from the one the controller loaded, 0 when they match, absent when it cannot be read.",
			nil, nil),
		info: prometheus.NewDesc(
			namespace+"_controller_config_info",
			"The digest of the manifest the controller is running on; value is always 1.",
			[]string{"effective_digest"}, nil),
	}
	reg.MustRegister(c)
	return c
}

func (c *ConfigCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.drift
	ch <- c.info
}

func (c *ConfigCollector) Collect(ch chan<- prometheus.Metric) {
	effective := c.eff.Digest()
	if effective == "" {
		// Nothing loaded yet: reporting 0 here would assert "in sync" about a
		// controller that has not read anything.
		return
	}
	ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1, effective)

	onDisk, err := config.DigestFile(c.path)
	if err != nil {
		// Emit nothing rather than 0 or 1. A manifest that cannot be read is its own
		// problem, and guessing either way here would either hide it or raise a drift
		// alarm for a cause drift does not describe.
		return
	}
	var drift float64
	if onDisk != effective {
		drift = 1
	}
	ch <- prometheus.MustNewConstMetric(c.drift, prometheus.GaugeValue, drift)
}
