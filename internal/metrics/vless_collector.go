package metrics

import (
	"context"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	statscmd "github.com/shidoh/wgfleet/internal/api/pb/third_party/xray/stats"
	"github.com/shidoh/wgfleet/internal/xray"
)

// vlessStatsTimeout bounds one read of xray's stats API during a scrape.
const vlessStatsTimeout = 2 * time.Second

// VLESSUserStats is one client-facing VLESS user as xray counts it. User is the
// xray "email" — domain.VLESSStatsID, never the UUID.
type VLESSUserStats struct {
	User     string
	Uplink   int64 // from the client (its upload)
	Downlink int64 // to the client (its download)
	// OnlineIPs is how many source IPs the user has open connections from.
	// OnlineKnown is false when the xray build cannot say (no GetUsersStats).
	OnlineIPs   int
	OnlineKnown bool
}

// VLESSStatsFunc reads every user's counters from the master's client-facing xray.
type VLESSStatsFunc func(ctx context.Context) ([]VLESSUserStats, error)

// VLESSCollector publishes per-client traffic of the master's client-facing VLESS
// inbound at scrape time, by asking xray's StatsService. It never resets xray's
// counters: they are monotonic until xray restarts, which is exactly a Prometheus
// counter, and a reset by one reader would silently eat another reader's traffic.
type VLESSCollector struct {
	enabled func() bool
	read    VLESSStatsFunc

	rx, tx, online, up *prometheus.Desc
}

var _ prometheus.Collector = (*VLESSCollector)(nil)

// NewVLESSCollector registers the collector. enabled reports whether this master's
// last applied spec runs the VLESS inbound; while it does not, the collector emits
// nothing. read nil ⇒ the gRPC client on xray.ClientStatsAPIAddr.
func NewVLESSCollector(reg *prometheus.Registry, node, role string, enabled func() bool, read VLESSStatsFunc) *VLESSCollector {
	if read == nil {
		read = func(ctx context.Context) ([]VLESSUserStats, error) {
			return xrayUserStats(ctx, xray.ClientStatsAPIAddr)
		}
	}
	cl := prometheus.Labels{"node": node, "role": role}
	payload := "decrypted payload without REALITY/XHTTP overhead. Cumulative; resets when xray restarts, so read it with rate()/increase()."
	c := &VLESSCollector{
		enabled: enabled,
		read:    read,
		rx: prometheus.NewDesc(prometheus.BuildFQName(namespace, "vless", "user_rx_bytes"),
			"Bytes received from a VLESS client (its upload), "+payload, []string{"user"}, cl),
		tx: prometheus.NewDesc(prometheus.BuildFQName(namespace, "vless", "user_tx_bytes"),
			"Bytes sent to a VLESS client (its download), "+payload, []string{"user"}, cl),
		online: prometheus.NewDesc(prometheus.BuildFQName(namespace, "vless", "user_online_ips"),
			"Source IPs this VLESS client has open connections from right now; > 0 means online. An IP can be several people behind one NAT.",
			[]string{"user"}, cl),
		up: prometheus.NewDesc(prometheus.BuildFQName(namespace, "vless", "collector_up"),
			"1 when the master's client-facing xray answered its stats API on this scrape, 0 when it did not. Absent on a master without the VLESS inbound.",
			nil, cl),
	}
	reg.MustRegister(c)
	return c
}

// Describe implements prometheus.Collector.
func (c *VLESSCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rx
	ch <- c.tx
	ch <- c.online
	ch <- c.up
}

// Collect implements prometheus.Collector.
func (c *VLESSCollector) Collect(ch chan<- prometheus.Metric) {
	if c.enabled == nil || !c.enabled() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), vlessStatsTimeout)
	defer cancel()
	users, err := c.read(ctx)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)
	for _, u := range users {
		if u.User == "" {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.rx, prometheus.CounterValue, float64(u.Uplink), u.User)
		ch <- prometheus.MustNewConstMetric(c.tx, prometheus.CounterValue, float64(u.Downlink), u.User)
		if u.OnlineKnown {
			ch <- prometheus.MustNewConstMetric(c.online, prometheus.GaugeValue, float64(u.OnlineIPs), u.User)
		}
	}
}

// xrayUserStats asks the local xray for every user's counters. Traffic comes from
// QueryStats, which lists every user xray has counted since it started. Online
// comes from GetUsersStats, which on 26.6.22 answers for the users online right
// now and nobody else — taking traffic from it too dropped every user the moment
// they disconnected (seen on the stand). An xray without GetUsersStats (an older
// operator-pinned image) still gives traffic, with online left unknown.
func xrayUserStats(ctx context.Context, addr string) ([]VLESSUserStats, error) {
	conn, err := grpc.NewClient("passthrough:///"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	cli := statscmd.NewStatsServiceClient(conn)

	q, err := cli.QueryStats(ctx, &statscmd.QueryStatsRequest{Pattern: "user>>>"})
	if err != nil {
		return nil, err
	}
	byUser := map[string]*VLESSUserStats{}
	var order []string
	for _, st := range q.GetStat() {
		user, dir := parseUserTrafficStat(st.GetName())
		if user == "" {
			continue
		}
		u, ok := byUser[user]
		if !ok {
			u = &VLESSUserStats{User: user}
			byUser[user] = u
			order = append(order, user)
		}
		if dir == "uplink" {
			u.Uplink = st.GetValue()
		} else {
			u.Downlink = st.GetValue()
		}
	}

	online, err := cli.GetUsersStats(ctx, &statscmd.GetUsersStatsRequest{})
	switch {
	case err == nil:
		for _, u := range byUser {
			u.OnlineKnown = true
		}
		for _, ou := range online.GetUsers() {
			if u, ok := byUser[ou.GetEmail()]; ok {
				u.OnlineIPs = len(ou.GetIps())
			}
		}
	case status.Code(err) != codes.Unimplemented:
		return nil, err
	}

	out := make([]VLESSUserStats, 0, len(order))
	for _, name := range order {
		out = append(out, *byUser[name])
	}
	return out, nil
}

// parseUserTrafficStat splits xray's "user>>>EMAIL>>>traffic>>>uplink|downlink".
// Any other counter name yields "", "".
func parseUserTrafficStat(name string) (user, dir string) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", ""
	}
	if parts[3] != "uplink" && parts[3] != "downlink" {
		return "", ""
	}
	return parts[1], parts[3]
}
