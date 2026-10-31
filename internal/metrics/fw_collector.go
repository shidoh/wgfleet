package metrics

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// nftListTimeout bounds the `nft -j list table inet wgfleet` exec per scrape.
const nftListTimeout = 3 * time.Second

// asBlacklistHitsCounter is netfw.ASBlacklistHitsCounter, the counter on the
// scanner-feed rule. Spelled out rather than imported, like the uplink prefix.
const asBlacklistHitsCounter = "as_blacklist_hits"

// NFTFunc returns the `nft -j list table inet wgfleet` JSON output. Injected so
// tests feed a fixture and so a missing nft / non-Linux box / absent table fails
// soft (an error yields no firewall series, no panic). Safe on every role: a
// node without the table simply emits nothing.
type NFTFunc func(ctx context.Context) ([]byte, error)

// FWCollector emits firewall telemetry at scrape time from nft table inet
// wgfleet: AS-blacklist set sizes, named drop counters, and on a master the
// handshake counters on its public address (uplink_*). Scrape-time
// (like StoreCollector) so there is no extra goroutine and the numbers are
// current as of the scrape.
type FWCollector struct {
	list NFTFunc

	blacklistSize *prometheus.Desc
	blacklistHits *prometheus.Desc
	drops         *prometheus.Desc
	handshakes    *prometheus.Desc
}

var _ prometheus.Collector = (*FWCollector)(nil)

// NewFWCollector builds the firewall collector, registering it on reg. node +
// role are constant labels (mirrors NewAgentMetrics). list defaults to a real
// `nft -j list table inet wgfleet` exec when nil.
func NewFWCollector(reg *prometheus.Registry, node, role string, list NFTFunc) *FWCollector {
	if list == nil {
		list = nftListTable
	}
	cl := prometheus.Labels{"node": node, "role": role}
	c := &FWCollector{
		list: list,
		blacklistSize: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "fw", "as_blacklist_size"),
			"Number of elements in the nftables AS-blacklist set, by address family.",
			[]string{"family"}, cl),
		blacklistHits: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "fw", "as_blacklist_hits_total"),
			"Packets opening a connection to this node from a scanner-feed network: dropped when the feed is enforced, only counted when it is observed. Replies to connections the node or its clients opened are never counted.",
			nil, cl),
		drops: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "fw", "drops_total"),
			"Packets dropped by a named nftables drop counter in table inet wgfleet.",
			[]string{"counter"}, cl),
		handshakes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "fw", "uplink_handshake_packets_total"),
			"TCP handshake packets crossing this master's public address: syn_out (SYNs it sent, retransmits included) and synack_in (answers it got).",
			[]string{"direction"}, cl),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *FWCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.blacklistSize
	ch <- c.blacklistHits
	ch <- c.drops
	ch <- c.handshakes
}

// Collect implements prometheus.Collector. An unreadable table (nft missing,
// table absent, non-Linux) yields no series rather than failing the scrape.
func (c *FWCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), nftListTimeout)
	defer cancel()

	out, err := c.list(ctx)
	if err != nil {
		return
	}
	stats, err := parseNFTTable(out)
	if err != nil {
		return
	}
	for family, size := range stats.blacklistSize {
		ch <- prometheus.MustNewConstMetric(c.blacklistSize, prometheus.GaugeValue, float64(size), family)
	}
	for name, packets := range stats.counters {
		if dir, ok := strings.CutPrefix(name, uplinkCounterPrefix); ok {
			ch <- prometheus.MustNewConstMetric(c.handshakes, prometheus.CounterValue, packets, dir)
			continue
		}
		if name == asBlacklistHitsCounter {
			ch <- prometheus.MustNewConstMetric(c.blacklistHits, prometheus.CounterValue, packets)
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.drops, prometheus.CounterValue, packets, name)
	}
}

// nftListTable runs the real `nft -j list table inet wgfleet`. A non-zero exit
// (no such table, nft not installed, non-Linux, not root) returns the error,
// which the collector treats as "no firewall series".
func nftListTable(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", "wgfleet").Output()
}
