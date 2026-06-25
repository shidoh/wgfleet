package metrics

import (
	"context"
	"os/exec"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// wgDumpTimeout bounds each `wg show <iface> dump` exec done during a scrape.
const wgDumpTimeout = 3 * time.Second

// recentHandshakeWindow is how fresh a peer's last handshake must be to count it
// as "active" for wgfleet_wg_peers_active. WireGuard re-handshakes about every
// two minutes when traffic flows, so three minutes tolerates one missed
// rekey without flapping the count.
const recentHandshakeWindow = 3 * time.Minute

// DumpFunc returns the `wg show <iface> dump` (or `awg show <iface> dump`) output
// for one interface. Injected so tests feed a fixture and so the collector is
// agnostic to wg vs awg. It must fail-soft: a missing tool / non-Linux box / down
// interface returns an error, which yields no series for that interface (no panic).
type DumpFunc func(ctx context.Context, iface string) (string, error)

// WGCollector emits per-peer WireGuard/AmneziaWG telemetry at scrape time, so
// there is no extra goroutine and the numbers are always current as of the
// scrape (matching the StoreCollector pattern). It probes a fixed set of the
// node's interfaces; an interface that does not exist simply contributes nothing.
type WGCollector struct {
	ifaces []string
	dump   DumpFunc
	now    func() time.Time

	handshakeAge *prometheus.Desc
	rxBytes      *prometheus.Desc
	txBytes      *prometheus.Desc
	peersActive  *prometheus.Desc
}

var _ prometheus.Collector = (*WGCollector)(nil)

// NewWGCollector builds a collector over the given interfaces, registering it on
// reg. node + role are attached as constant labels so a Prometheus scraping each
// node's /metrics groups cleanly by node (mirrors NewAgentMetrics). dump defaults
// to a real `wg show <iface> dump` exec when nil.
func NewWGCollector(reg *prometheus.Registry, node, role string, ifaces []string, dump DumpFunc) *WGCollector {
	if dump == nil {
		dump = wgShowDump
	}
	cl := prometheus.Labels{"node": node, "role": role}
	c := &WGCollector{
		ifaces: ifaces,
		dump:   dump,
		now:    time.Now,
		handshakeAge: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wg", "handshake_age_seconds"),
			"Seconds since a WireGuard/AmneziaWG peer's last handshake (absent if it never handshook).",
			[]string{"iface", "peer"}, cl),
		rxBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wg", "peer_rx_bytes"),
			"Bytes received from a WireGuard/AmneziaWG peer (cumulative, resets on interface re-create).",
			[]string{"iface", "peer"}, cl),
		txBytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wg", "peer_tx_bytes"),
			"Bytes transmitted to a WireGuard/AmneziaWG peer (cumulative, resets on interface re-create).",
			[]string{"iface", "peer"}, cl),
		peersActive: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "wg", "peers_active"),
			"Number of peers on an interface with a handshake within the recent window.",
			[]string{"iface"}, cl),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *WGCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.handshakeAge
	ch <- c.rxBytes
	ch <- c.txBytes
	ch <- c.peersActive
}

// Collect implements prometheus.Collector. Each interface is probed
// independently; an unreadable interface (tool missing, iface down) contributes
// no series rather than failing the scrape.
func (c *WGCollector) Collect(ch chan<- prometheus.Metric) {
	now := c.now()
	for _, iface := range c.ifaces {
		ctx, cancel := context.WithTimeout(context.Background(), wgDumpTimeout)
		out, err := c.dump(ctx, iface)
		cancel()
		if err != nil {
			continue
		}
		peers := parseWGDump(out)
		active := 0
		for _, p := range peers {
			id := shortPeerID(p.publicKey)
			ch <- prometheus.MustNewConstMetric(c.rxBytes, prometheus.GaugeValue, p.rxBytes, iface, id)
			ch <- prometheus.MustNewConstMetric(c.txBytes, prometheus.GaugeValue, p.txBytes, iface, id)
			if p.latestHandshake > 0 {
				age := now.Sub(time.Unix(p.latestHandshake, 0)).Seconds()
				ch <- prometheus.MustNewConstMetric(c.handshakeAge, prometheus.GaugeValue, age, iface, id)
				if age <= recentHandshakeWindow.Seconds() {
					active++
				}
			}
		}
		ch <- prometheus.MustNewConstMetric(c.peersActive, prometheus.GaugeValue, float64(active), iface)
	}
}

// wgShowDump runs the real `wg show <iface> dump`. AmneziaWG's `awg` produces the
// identical dump format, but `wg` reads awg kernel interfaces too, so one command
// covers both. A non-zero exit (no such interface, wg not installed, non-Linux)
// returns the error, which the collector treats as "no series".
func wgShowDump(ctx context.Context, iface string) (string, error) {
	out, err := exec.CommandContext(ctx, "wg", "show", iface, "dump").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
