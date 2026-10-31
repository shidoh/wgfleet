package metrics

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/asnfeed"
)

// FeedCollector reports what each scanner-feed source contributed to the last
// good list, read at scrape time from the header of the feed cache. The kernel
// set size (wgfleet_fw_as_blacklist_size) says how big the list is; this says
// which source moved when it changes size — C24Be has published half its usual
// list on a bad day and been taken whole.
type FeedCollector struct {
	cachePath string
	prefixes  *prometheus.Desc
	addresses *prometheus.Desc
}

var _ prometheus.Collector = (*FeedCollector)(nil)

// NewFeedCollector registers the collector for the cache at cachePath. A node
// whose feed is off has no cache and emits nothing.
func NewFeedCollector(reg *prometheus.Registry, node, role, cachePath string) *FeedCollector {
	cl := prometheus.Labels{"node": node, "role": role}
	c := &FeedCollector{
		cachePath: cachePath,
		prefixes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "fw", "as_blacklist_source_prefixes"),
			"Prefixes one scanner-feed source contributed to the last good list, by address family.",
			[]string{"source", "family"}, cl),
		addresses: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "fw", "as_blacklist_source_ipv4_addresses"),
			"IPv4 addresses one scanner-feed source covers in the last good list, overlaps counted once.",
			[]string{"source"}, cl),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *FeedCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.prefixes
	ch <- c.addresses
}

// Collect implements prometheus.Collector. A missing or unreadable cache yields
// no series rather than failing the scrape.
func (c *FeedCollector) Collect(ch chan<- prometheus.Metric) {
	f, err := os.Open(c.cachePath)
	if err != nil {
		return
	}
	defer f.Close()
	sources, err := asnfeed.DecodeSources(f)
	if err != nil {
		return
	}
	for _, s := range sources {
		ch <- prometheus.MustNewConstMetric(c.prefixes, prometheus.GaugeValue, float64(s.V4), s.URL, "v4")
		ch <- prometheus.MustNewConstMetric(c.prefixes, prometheus.GaugeValue, float64(s.V6), s.URL, "v6")
		ch <- prometheus.MustNewConstMetric(c.addresses, prometheus.GaugeValue, float64(s.V4Addresses), s.URL)
	}
}
