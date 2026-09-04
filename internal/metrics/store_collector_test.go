package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func newCollectorWithStore(t *testing.T) (*prometheus.Registry, store.Store, *StoreCollector) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := prometheus.NewRegistry()
	c := NewStoreCollector(reg, st)
	c.now = func() time.Time { return time.Unix(1_700_000_100, 0) } // fixed clock
	return reg, st, c
}

func TestStoreCollectorNodeStates(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, Region: "de", State: domain.StateReady})
	_ = st.UpsertNode(ctx, domain.Node{ID: "exit-nl-1", Name: "exit-nl-1", Role: domain.RoleExit, State: domain.StateReady})
	_ = st.UpsertNode(ctx, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateDegraded})

	want := `
# HELP wgfleet_nodes Number of fleet nodes in each lifecycle state.
# TYPE wgfleet_nodes gauge
wgfleet_nodes{state="Degraded"} 1
wgfleet_nodes{state="Error"} 0
wgfleet_nodes{state="Pending"} 0
wgfleet_nodes{state="Provisioning"} 0
wgfleet_nodes{state="Ready"} 2
wgfleet_nodes{state="Reconciling"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_nodes"); err != nil {
		t.Error(err)
	}
}

func TestStoreCollectorNodeInfoAndReconcile(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, Region: "de", State: domain.StateReady})
	_ = st.SetNodeState(ctx, "exit-de-1", domain.StateError, "nft failed")

	wantInfo := `
# HELP wgfleet_node_info Static node inventory info; value is always 1.
# TYPE wgfleet_node_info gauge
wgfleet_node_info{node="exit-de-1",region="de",role="exit",state="Error"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantInfo), "wgfleet_node_info"); err != nil {
		t.Error(err)
	}

	wantNG := `
# HELP wgfleet_node_reconcile_failed 1 if the node's last reconcile/provision recorded an error, else 0.
# TYPE wgfleet_node_reconcile_failed gauge
wgfleet_node_reconcile_failed{node="exit-de-1"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantNG), "wgfleet_node_reconcile_failed"); err != nil {
		t.Error(err)
	}
}

func TestStoreCollectorHealthChecksAndEgress(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateDegraded})
	_ = st.RecordStatus(ctx, domain.NodeStatus{
		NodeID: "exit-de-1", State: domain.StateDegraded, EgressIP: "104.16.0.1",
		Checks: []domain.HealthCheck{
			{Name: "warp-egress", OK: true},
			{Name: "dns-filter", OK: false},
		},
	})

	wantChecks := `
# HELP wgfleet_node_health_check Result of a node self-check: 1 ok, 0 failing.
# TYPE wgfleet_node_health_check gauge
wgfleet_node_health_check{check="dns-filter",node="exit-de-1"} 0
wgfleet_node_health_check{check="warp-egress",node="exit-de-1"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantChecks), "wgfleet_node_health_check"); err != nil {
		t.Error(err)
	}

	wantEgress := `
# HELP wgfleet_node_egress_info Observed egress IP as a label; value is always 1.
# TYPE wgfleet_node_egress_info gauge
wgfleet_node_egress_info{egress_ip="104.16.0.1",node="exit-de-1"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantEgress), "wgfleet_node_egress_info"); err != nil {
		t.Error(err)
	}
}

func TestStoreCollectorClientVLESSClients(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady})
	_ = st.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})
	_ = st.AddVLESSClient(ctx, "master-xa-1", domain.VLESSClient{Name: "phone", UUID: "u-phone"})
	_ = st.AddVLESSClient(ctx, "master-xa-1", domain.VLESSClient{Name: "laptop", UUID: "u-laptop"})

	// Masters report their issued client count (ADR-0031); exits, which never run
	// the client-facing inbound, are absent from this gauge entirely.
	want := `
# HELP wgfleet_node_client_vless_clients Number of VLESS/REALITY clients issued for a master's client-facing inbound (ADR-0031).
# TYPE wgfleet_node_client_vless_clients gauge
wgfleet_node_client_vless_clients{node="master-xa-1"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_node_client_vless_clients"); err != nil {
		t.Error(err)
	}
}

func TestStoreCollectorLastReportAge(t *testing.T) {
	_, st, c := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})
	// RecordStatus stamps last_seen; the age metric is then present for the node.
	_ = st.RecordStatus(ctx, domain.NodeStatus{NodeID: "exit-de-1", State: domain.StateReady})

	got := testutil.CollectAndCount(c, "wgfleet_node_last_report_age_seconds")
	if got != 1 {
		t.Errorf("expected 1 last_report metric, got %d", got)
	}
}

func TestStoreCollectorEmptyFleet(t *testing.T) {
	reg, _, _ := newCollectorWithStore(t)
	// All state gauges present at 0 even with no nodes.
	want := `
# HELP wgfleet_nodes Number of fleet nodes in each lifecycle state.
# TYPE wgfleet_nodes gauge
wgfleet_nodes{state="Degraded"} 0
wgfleet_nodes{state="Error"} 0
wgfleet_nodes{state="Pending"} 0
wgfleet_nodes{state="Provisioning"} 0
wgfleet_nodes{state="Ready"} 0
wgfleet_nodes{state="Reconciling"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_nodes"); err != nil {
		t.Error(err)
	}
}

func TestAgentMetricsObserve(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))

	m.ObserveReconcile(120*time.Millisecond, 3, domain.StateReady,
		[]domain.HealthCheck{{Name: "warp-egress", OK: true}, {Name: "dns-filter", OK: false}}, nil)

	wantState := `
# HELP wgfleet_agent_state_info Current node lifecycle state as a label; value is always 1.
# TYPE wgfleet_agent_state_info gauge
wgfleet_agent_state_info{node="exit-de-1",role="exit",state="Ready"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantState), "wgfleet_agent_state_info"); err != nil {
		t.Error(err)
	}
	wantChecks := `
# HELP wgfleet_agent_health_check Result of a self-check: 1 ok, 0 failing.
# TYPE wgfleet_agent_health_check gauge
wgfleet_agent_health_check{check="dns-filter",node="exit-de-1",role="exit"} 0
wgfleet_agent_health_check{check="warp-egress",node="exit-de-1",role="exit"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantChecks), "wgfleet_agent_health_check"); err != nil {
		t.Error(err)
	}
	if got := testutil.ToFloat64(m.reconcileTotal.WithLabelValues("success")); got != 1 {
		t.Errorf("reconcile success counter = %v", got)
	}
	if got := testutil.ToFloat64(m.reconcileChanges); got != 3 {
		t.Errorf("reconcile_changes = %v, want 3", got)
	}

	// A failing reconcile updates state to Error and bumps the error counter.
	m.ObserveReconcile(5*time.Millisecond, 0, domain.StateError, nil, errContext)
	if got := testutil.ToFloat64(m.reconcileTotal.WithLabelValues("error")); got != 1 {
		t.Errorf("reconcile error counter = %v", got)
	}
	// state_info must reflect ONLY the latest state (single-valued).
	if got := testutil.CollectAndCount(m.stateInfo); got != 1 {
		t.Errorf("state_info should be single-valued, got %d series", got)
	}
}

func TestAgentMetricsObserveDrift(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))

	// First drift pass: two components diverged and were repaired.
	m.ObserveDrift([]string{"policy routing", "firewall (nftables)"})
	if got := testutil.ToFloat64(m.driftResources); got != 2 {
		t.Errorf("drift_resources = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.driftTotal.WithLabelValues("policy routing")); got != 1 {
		t.Errorf("drift_total{policy routing} = %v, want 1", got)
	}

	// Repeated drift on the same component accumulates in the counter...
	m.ObserveDrift([]string{"policy routing"})
	if got := testutil.ToFloat64(m.driftTotal.WithLabelValues("policy routing")); got != 2 {
		t.Errorf("drift_total{policy routing} = %v, want 2", got)
	}
	// ...while the gauge reflects only the last pass.
	if got := testutil.ToFloat64(m.driftResources); got != 1 {
		t.Errorf("drift_resources = %v, want 1", got)
	}

	// A clean pass (no drift) resets the gauge to 0 but leaves the counter.
	m.ObserveDrift(nil)
	if got := testutil.ToFloat64(m.driftResources); got != 0 {
		t.Errorf("drift_resources after clean pass = %v, want 0", got)
	}
	if got := testutil.ToFloat64(m.driftTotal.WithLabelValues("policy routing")); got != 2 {
		t.Errorf("drift_total must persist across clean pass, got %v", got)
	}
}

var errContext = errString("nft failed")

type errString string

func (e errString) Error() string { return string(e) }

// The master's view of each master↔exit tunnel is the ONLY record of whether an
// exit is carrying traffic: the tunnels are userspace mihomo proxies, not kernel
// WireGuard, so no wg_* series covers them. It reached the store already (the
// agent has reported ExitHealth since the exit-tunnel work) but was never
// exported, which is why an exit dropping out of the load balancer could not be
// seen on a dashboard at all — the 2026-09-04 investigation had to be
// reconstructed from the master agent's journal.
func TestStoreCollectorExitTunnelHealth(t *testing.T) {
	reg, st, c := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady})
	_ = st.RecordStatus(ctx, domain.NodeStatus{
		NodeID: "master-xa-1", State: domain.StateReady,
		ExitHealth: []domain.ExitTunnelHealth{
			{Name: "vn0", Alive: true, Delay: 92 * time.Millisecond, Selected: true,
				LastTest: c.now().Add(-15 * time.Second)},
			{Name: "vn1", Alive: false, Selected: false,
				LastTest: c.now().Add(-45 * time.Second)},
		},
	})

	wantAlive := `
# HELP wgfleet_exit_tunnel_alive 1 when the master's mihomo reports this master↔exit tunnel up, 0 when it is out of the load-balance rotation.
# TYPE wgfleet_exit_tunnel_alive gauge
wgfleet_exit_tunnel_alive{exit="vn0",node="master-xa-1"} 1
wgfleet_exit_tunnel_alive{exit="vn1",node="master-xa-1"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantAlive), "wgfleet_exit_tunnel_alive"); err != nil {
		t.Error(err)
	}

	wantSelected := `
# HELP wgfleet_exit_tunnel_selected 1 when this exit currently carries traffic for the master's wg-best group, else 0.
# TYPE wgfleet_exit_tunnel_selected gauge
wgfleet_exit_tunnel_selected{exit="vn0",node="master-xa-1"} 1
wgfleet_exit_tunnel_selected{exit="vn1",node="master-xa-1"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantSelected), "wgfleet_exit_tunnel_selected"); err != nil {
		t.Error(err)
	}

	// A measurement's AGE is half the signal. mihomo's alive flag is sticky: it
	// keeps whatever the last probe wrote, so a master whose agent stopped probing
	// reports a confidently "alive" tunnel forever. Without the age, a frozen view
	// and a healthy one are the same series.
	wantAge := `
# HELP wgfleet_exit_tunnel_last_test_age_seconds Seconds since the last delay measurement of this tunnel. mihomo's alive flag is sticky, so a stale age means the reading is frozen, not that the tunnel is fine.
# TYPE wgfleet_exit_tunnel_last_test_age_seconds gauge
wgfleet_exit_tunnel_last_test_age_seconds{exit="vn0",node="master-xa-1"} 15
wgfleet_exit_tunnel_last_test_age_seconds{exit="vn1",node="master-xa-1"} 45
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantAge), "wgfleet_exit_tunnel_last_test_age_seconds"); err != nil {
		t.Error(err)
	}
}

// Delay 0 means "no measurement / the probe failed", not "answered instantly".
// Emitting it as 0 seconds would make a dead tunnel the best-looking one on any
// latency panel or url-test alert, so the series is omitted and `alive` carries
// the failure instead.
func TestStoreCollectorOmitsDelayWhenUnmeasured(t *testing.T) {
	reg, st, _ := newCollectorWithStore(t)
	ctx := context.Background()
	_ = st.UpsertNode(ctx, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady})
	_ = st.RecordStatus(ctx, domain.NodeStatus{
		NodeID: "master-xa-1", State: domain.StateReady,
		ExitHealth: []domain.ExitTunnelHealth{
			{Name: "vn0", Alive: true, Delay: 92 * time.Millisecond},
			{Name: "vn1", Alive: false, Delay: 0},
		},
	})

	want := `
# HELP wgfleet_exit_tunnel_delay_seconds Last url-test delay of this master↔exit tunnel, in seconds. Absent when the last measurement failed — a failed probe is not a fast one, so it must never read as 0.
# TYPE wgfleet_exit_tunnel_delay_seconds gauge
wgfleet_exit_tunnel_delay_seconds{exit="vn0",node="master-xa-1"} 0.092
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_exit_tunnel_delay_seconds"); err != nil {
		t.Error(err)
	}
}
