package metrics

import (
	"context"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// scrapeTimeout bounds the store queries done during a metrics scrape.
const scrapeTimeout = 5 * time.Second

// nodeStates is the fixed label set for the per-state node gauge, so a state
// with zero nodes still reports 0 (not absent).
var nodeStates = []domain.NodeState{
	domain.StatePending, domain.StateProvisioning, domain.StateReconciling,
	domain.StateReady, domain.StateDegraded, domain.StateError,
}

// StoreCollector projects the controller's state store into Prometheus metrics
// at scrape time, so there are no counters to keep in sync with the store.
type StoreCollector struct {
	store store.Store
	now   func() time.Time

	nodesByState     *prometheus.Desc
	nodeInfo         *prometheus.Desc
	nodeLastReport   *prometheus.Desc
	nodeReconcileNG  *prometheus.Desc
	nodeHealthCheck  *prometheus.Desc
	nodeEgressInfo   *prometheus.Desc
	nodeAgentInfo    *prometheus.Desc
	nodeDrain        *prometheus.Desc
	nodeDecommission *prometheus.Desc
}

var _ prometheus.Collector = (*StoreCollector)(nil)

// NewStoreCollector builds a collector over the given store and registers it on
// reg.
func NewStoreCollector(reg *prometheus.Registry, st store.Store) *StoreCollector {
	c := &StoreCollector{
		store: st,
		now:   time.Now,
		nodesByState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "nodes"),
			"Number of fleet nodes in each lifecycle state.",
			[]string{"state"}, nil),
		nodeInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "info"),
			"Static node inventory info; value is always 1.",
			[]string{"node", "role", "region", "state"}, nil),
		nodeLastReport: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "last_report_age_seconds"),
			"Seconds since the node last reported status (absent if never).",
			[]string{"node"}, nil),
		nodeReconcileNG: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "reconcile_failed"),
			"1 if the node's last reconcile/provision recorded an error, else 0.",
			[]string{"node"}, nil),
		nodeHealthCheck: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "health_check"),
			"Result of a node self-check: 1 ok, 0 failing.",
			[]string{"node", "check"}, nil),
		nodeEgressInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "egress_info"),
			"Observed egress IP as a label; value is always 1.",
			[]string{"node", "egress_ip"}, nil),
		nodeAgentInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "agent_info"),
			"Agent build + wire version reported by the node; value is always 1.",
			[]string{"node", "agent_version", "wire_version"}, nil),
		nodeDrain: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "drain"),
			"1 if the node is administratively drained (out of the LB, connections preserved), else 0.",
			[]string{"node"}, nil),
		nodeDecommission: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "decommission"),
			"1 if the node is flagged for decommission (data plane torn down), else 0.",
			[]string{"node"}, nil),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *StoreCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.nodesByState
	ch <- c.nodeInfo
	ch <- c.nodeLastReport
	ch <- c.nodeReconcileNG
	ch <- c.nodeHealthCheck
	ch <- c.nodeEgressInfo
	ch <- c.nodeAgentInfo
	ch <- c.nodeDrain
	ch <- c.nodeDecommission
}

// Collect implements prometheus.Collector. Store errors yield no metrics for
// this scrape rather than a partial/garbage view.
func (c *StoreCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()

	nodes, err := c.store.ListNodes(ctx)
	if err != nil {
		return
	}

	counts := map[domain.NodeState]int{}
	for _, n := range nodes {
		counts[n.State]++

		ch <- prometheus.MustNewConstMetric(c.nodeInfo, prometheus.GaugeValue, 1,
			n.Name, string(n.Role), n.Region, string(n.State))

		if !n.LastSeen.IsZero() {
			age := c.now().Sub(n.LastSeen).Seconds()
			ch <- prometheus.MustNewConstMetric(c.nodeLastReport, prometheus.GaugeValue, age, n.Name)
		}
		ch <- prometheus.MustNewConstMetric(c.nodeReconcileNG, prometheus.GaugeValue,
			boolToFloat(n.LastError != ""), n.Name)
		ch <- prometheus.MustNewConstMetric(c.nodeDrain, prometheus.GaugeValue,
			boolToFloat(n.Drain), n.Name)
		ch <- prometheus.MustNewConstMetric(c.nodeDecommission, prometheus.GaugeValue,
			boolToFloat(n.Decommission), n.Name)

		if n.AgentVersion != "" || n.WireVersion != 0 {
			ch <- prometheus.MustNewConstMetric(c.nodeAgentInfo, prometheus.GaugeValue, 1,
				n.Name, n.AgentVersion, strconv.FormatUint(uint64(n.WireVersion), 10))
		}

		c.collectStatus(ctx, ch, n.Name)
	}

	for _, st := range nodeStates {
		ch <- prometheus.MustNewConstMetric(c.nodesByState, prometheus.GaugeValue,
			float64(counts[st]), string(st))
	}
}

func (c *StoreCollector) collectStatus(ctx context.Context, ch chan<- prometheus.Metric, node string) {
	st, err := c.store.GetStatus(ctx, node)
	if err != nil {
		return
	}
	for _, hc := range st.Checks {
		ch <- prometheus.MustNewConstMetric(c.nodeHealthCheck, prometheus.GaugeValue,
			boolToFloat(hc.OK), node, hc.Name)
	}
	if st.EgressIP != "" {
		ch <- prometheus.MustNewConstMetric(c.nodeEgressInfo, prometheus.GaugeValue, 1, node, st.EgressIP)
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
