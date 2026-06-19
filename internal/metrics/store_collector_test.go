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
