package metrics

import (
	"context"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// bridgeReadTimeout bounds one read of the bridge's sockets during a scrape.
const bridgeReadTimeout = 3 * time.Second

// BridgeConnsFunc returns the exit's established bridge connections per master
// (ADR-0038), every portal of the spec present, a disconnected one with zero;
// empty outside the exit-initiated REALITY mode.
type BridgeConnsFunc func(ctx context.Context) (map[string]int, error)

// BridgeCollector publishes, per master, whether the exit's reality bridge holds
// a connection to its portal, and how many stalled sockets the watchdog killed.
// The exit's health check only asks for one master; this is where a single
// master's path going dark shows.
type BridgeCollector struct {
	conns BridgeConnsFunc
	kills func() map[string]uint64

	connected, killed *prometheus.Desc
}

var _ prometheus.Collector = (*BridgeCollector)(nil)

// NewBridgeCollector registers the collector on an exit.
func NewBridgeCollector(reg *prometheus.Registry, node, role string, conns BridgeConnsFunc, kills func() map[string]uint64) *BridgeCollector {
	cl := prometheus.Labels{"node": node, "role": role}
	c := &BridgeCollector{
		conns: conns,
		kills: kills,
		connected: prometheus.NewDesc(prometheus.BuildFQName(namespace, "agent", "reality_bridge_connected"),
			"1 when the exit's reality bridge holds an established connection to this master's portal, 0 when it holds none. Absent outside the exit-initiated REALITY mode.",
			[]string{"master"}, cl),
		killed: prometheus.NewDesc(prometheus.BuildFQName(namespace, "agent", "reality_bridge_kills_total"),
			"Bridge sockets to this master's portal the watchdog killed because they received nothing for 30 s — one-way freezes on that path.",
			[]string{"master"}, cl),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *BridgeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.connected
	ch <- c.killed
}

// Collect implements prometheus.Collector.
func (c *BridgeCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), bridgeReadTimeout)
	defer cancel()
	conns, err := c.conns(ctx)
	kills := map[string]uint64{}
	if c.kills != nil {
		kills = c.kills()
	}
	masters := map[string]bool{}
	for m := range conns {
		masters[m] = true
	}
	for m := range kills {
		masters[m] = true
	}
	if len(conns) == 0 && err == nil {
		return // not in the mode
	}
	names := make([]string, 0, len(masters))
	for m := range masters {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		if err == nil {
			up := 0.0
			if conns[m] > 0 {
				up = 1
			}
			ch <- prometheus.MustNewConstMetric(c.connected, prometheus.GaugeValue, up, m)
		}
		ch <- prometheus.MustNewConstMetric(c.killed, prometheus.CounterValue, float64(kills[m]), m)
	}
}
