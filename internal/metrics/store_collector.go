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
	nodeAWGModule    *prometheus.Desc
	nodeDrain        *prometheus.Desc
	nodeDecommission *prometheus.Desc
	nodeVLESSClients *prometheus.Desc
	// clientInfo names the client behind each peer public key. The agents report
	// traffic per peer key only — they never see names — so without it a per-client
	// panel reads "Zg4vfVc4…: 6 Mbit/s".
	clientInfo *prometheus.Desc
	// The master's view of each master↔exit tunnel. These tunnels are userspace
	// mihomo proxies, not kernel WireGuard, so NO wg_* series covers them — this is
	// their only representation in metrics. Their absence is what made an exit
	// dropping out of the load balancer invisible on every dashboard: an
	// investigation had to be reconstructed from the master agent's
	// journal because nothing recorded which exits were in rotation when.
	exitTunnelAlive    *prometheus.Desc
	exitTunnelDelay    *prometheus.Desc
	exitTunnelSelected *prometheus.Desc
	exitTunnelTestAge  *prometheus.Desc
	// storeUp is 1 when this scrape read the store, 0 when it could not. Without it
	// a read error made the WHOLE fleet surface vanish while /metrics still answered
	// 200 — so `up` stayed 1 and the fleet-wide rules read the silence as fact:
	// WgfleetNoReadyExit paged critical with "every exit is out of rotation" for a
	// locked SQLite file, with the data plane untouched. WGCollector already learned
	// this; its sibling had not.
	storeUp *prometheus.Desc
}

var _ prometheus.Collector = (*StoreCollector)(nil)

// NewStoreCollector builds a collector over the given store and registers it on
// reg.
func NewStoreCollector(reg *prometheus.Registry, st store.Store) *StoreCollector {
	c := &StoreCollector{
		store: st,
		now:   time.Now,
		storeUp: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "controller", "store_up"),
			"1 when the controller could read its store on this scrape, 0 when it could not. Gate fleet-wide rules on this: without it an unreadable store looks exactly like an empty fleet.",
			nil, nil),
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
		nodeAWGModule: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "awg_module_info"),
			"AmneziaWG kernel module build the node runs (amneziawg-dkms build timestamp, or \"unknown\") and the module's srcversion; value is always 1.",
			[]string{"node", "build", "srcversion"}, nil),
		nodeDrain: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "drain"),
			"1 if the node is administratively drained (out of the LB, connections preserved), else 0.",
			[]string{"node"}, nil),
		nodeDecommission: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "decommission"),
			"1 if the node is flagged for decommission (data plane torn down), else 0.",
			[]string{"node"}, nil),
		clientInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "client_info"),
			"Client credential behind a per-client series key; value is always 1. kind=awg: peer is the WireGuard key in the agents' short form — join wgfleet_wg_peer_*{peer} on the master's wg0 and an exit's lifeline interface. kind=vless: peer is the VLESS stats id — join wgfleet_vless_user_*{user}.",
			[]string{"node", "peer", "client", "device", "kind"}, nil),
		nodeVLESSClients: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "node", "client_vless_clients"),
			"Number of VLESS/REALITY clients issued for a master's client-facing inbound (ADR-0031).",
			[]string{"node"}, nil),
		exitTunnelAlive: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "exit_tunnel", "alive"),
			"1 when the master's mihomo reports this master↔exit tunnel up, 0 when it is out of the load-balance rotation.",
			[]string{"node", "exit"}, nil),
		exitTunnelDelay: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "exit_tunnel", "delay_seconds"),
			"Last url-test delay of this master↔exit tunnel, in seconds. Absent when the last measurement failed — a failed probe is not a fast one, so it must never read as 0.",
			[]string{"node", "exit"}, nil),
		exitTunnelSelected: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "exit_tunnel", "selected"),
			"1 when this exit currently carries traffic for the master's wg-best group, else 0.",
			[]string{"node", "exit"}, nil),
		exitTunnelTestAge: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "exit_tunnel", "last_test_age_seconds"),
			"Seconds since the last delay measurement of this tunnel. mihomo's alive flag is sticky, so a stale age means the reading is frozen, not that the tunnel is fine.",
			[]string{"node", "exit"}, nil),
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
	ch <- c.nodeAWGModule
	ch <- c.nodeDrain
	ch <- c.nodeDecommission
	ch <- c.nodeVLESSClients
	ch <- c.clientInfo
	ch <- c.exitTunnelAlive
	ch <- c.exitTunnelDelay
	ch <- c.exitTunnelSelected
	ch <- c.exitTunnelTestAge
	ch <- c.storeUp
}

// Collect implements prometheus.Collector. Store errors yield no metrics for
// this scrape rather than a partial/garbage view.
func (c *StoreCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()

	nodes, err := c.store.ListNodes(ctx)
	if err != nil {
		// Say so, then stop. Emitting nothing at all is what made a read error
		// indistinguishable from a fleet with no nodes in it.
		ch <- prometheus.MustNewConstMetric(c.storeUp, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.storeUp, prometheus.GaugeValue, 1)

	devices := c.deviceNames(ctx)
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
		// Emitted for every node, unknown included: the module version cannot tell
		// builds apart, and "which nodes would hold a build-gated feature back" is
		// exactly the count of build="unknown" plus the too-old ones.
		ch <- prometheus.MustNewConstMetric(c.nodeAWGModule, prometheus.GaugeValue, 1,
			n.Name, n.AWGModule.Label(), n.AWGModule.SrcVersion)

		// Only masters run the client-facing VLESS inbound (ADR-0031). Emitting the
		// gauge just for masters keeps exits out of the series entirely rather than
		// reporting a misleading 0.
		if n.Role == domain.RoleMaster {
			if clients, err := c.store.ListVLESSClients(ctx, n.ID); err == nil {
				ch <- prometheus.MustNewConstMetric(c.nodeVLESSClients, prometheus.GaugeValue,
					float64(len(clients)), n.Name)
			}
			c.collectClients(ctx, ch, n, devices)
		}

		c.collectStatus(ctx, ch, n.Name)
	}

	for _, st := range nodeStates {
		ch <- prometheus.MustNewConstMetric(c.nodesByState, prometheus.GaugeValue,
			float64(counts[st]), string(st))
	}
}

// deviceNames maps (kind, master ID, credential ref) of every credential attached
// to a device to that device's name. The ref is the credential ID for AWG and the
// client label for VLESS (see domain.DeviceCredential). A read error yields an
// empty map: the clients are still named, only without their device.
func (c *StoreCollector) deviceNames(ctx context.Context) map[[3]string]string {
	out := map[[3]string]string{}
	devs, err := c.store.ListDevices(ctx)
	if err != nil {
		return out
	}
	for _, d := range devs {
		for _, cr := range d.Credentials {
			out[[3]string{string(cr.Kind), cr.MasterID, cr.Ref}] = d.Name
		}
	}
	return out
}

// collectClients emits one wgfleet_client_info per issued WireGuard credential of
// a master, muted ones included: a muted client keeps its traffic history and
// that history should keep its name. Only public fields reach labels — the
// metrics endpoint is unauthenticated and WGClient also holds the private key.
func (c *StoreCollector) collectClients(ctx context.Context, ch chan<- prometheus.Metric, n domain.Node, devices map[[3]string]string) {
	if clients, err := c.store.ListWGClients(ctx, n.ID); err == nil {
		for _, cl := range clients {
			if cl.PublicKey == "" {
				continue
			}
			// The agent labels peers with shortPeerID, not the whole key; anything
			// else here and the join on(peer) matches nothing.
			ch <- prometheus.MustNewConstMetric(c.clientInfo, prometheus.GaugeValue, 1,
				n.Name, shortPeerID(cl.PublicKey), cl.Name,
				devices[[3]string{string(domain.CredentialAWG), n.ID, cl.ID}], string(domain.CredentialAWG))
		}
	}
	// The VLESS UUID is a credential and this endpoint is open: only its stats id
	// — the same one the inbound counts under — ever reaches a label.
	if clients, err := c.store.ListVLESSClients(ctx, n.ID); err == nil {
		for _, cl := range clients {
			if cl.UUID == "" {
				continue
			}
			ch <- prometheus.MustNewConstMetric(c.clientInfo, prometheus.GaugeValue, 1,
				n.Name, domain.VLESSStatsID(cl.UUID), cl.Name,
				devices[[3]string{string(domain.CredentialVLESS), n.ID, cl.Name}], string(domain.CredentialVLESS))
		}
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
	// Only a master reports ExitHealth, so exits contribute nothing here and the
	// series stays scoped to the node that actually holds the tunnels.
	for _, h := range st.ExitHealth {
		ch <- prometheus.MustNewConstMetric(c.exitTunnelAlive, prometheus.GaugeValue,
			boolToFloat(h.Alive), node, h.Name)
		ch <- prometheus.MustNewConstMetric(c.exitTunnelSelected, prometheus.GaugeValue,
			boolToFloat(h.Selected), node, h.Name)
		// Delay 0 is "not measured / probe failed", never "answered instantly".
		// Reporting it as zero seconds would put a dead tunnel at the top of every
		// latency panel and under every url-test threshold; alive carries that case.
		if h.Delay > 0 {
			ch <- prometheus.MustNewConstMetric(c.exitTunnelDelay, prometheus.GaugeValue,
				h.Delay.Seconds(), node, h.Name)
		}
		if !h.LastTest.IsZero() {
			ch <- prometheus.MustNewConstMetric(c.exitTunnelTestAge, prometheus.GaugeValue,
				c.now().Sub(h.LastTest).Seconds(), node, h.Name)
		}
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
