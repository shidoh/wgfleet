package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/domain"
)

// transport_active is exit-only (ADR-0025). On a master it must not be registered
// at all — an empty series there makes absent()-based alerts fire spuriously.
func TestTransportActiveExitOnly(t *testing.T) {
	t.Run("exit registers and observes", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))
		m.ObserveTransport(domain.TransportRealityXHTTP)

		want := `
# HELP wgfleet_agent_transport_active Active master↔exit transport as a label (awg|reality-xhttp); value is always 1 (ADR-0025). Exit nodes only.
# TYPE wgfleet_agent_transport_active gauge
wgfleet_agent_transport_active{node="exit-de-1",role="exit",transport="reality-xhttp"} 1
`
		if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_transport_active"); err != nil {
			t.Error(err)
		}
	})

	t.Run("master never registers the series", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
		// Must be a safe no-op, not a nil-map panic.
		m.ObserveTransport(domain.TransportAWG)

		if n := testutil.CollectAndCount(reg, "wgfleet_agent_transport_active"); n != 0 {
			t.Errorf("master must expose no transport_active series, got %d", n)
		}
	})
}

// The tier series are master-only: exits have no tier decision to report, and an
// empty series on every exit would make absent()-based rules fire fleet-wide.
func TestTierMetricsAreMasterOnly(t *testing.T) {
	t.Run("master registers and observes", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
		m.ObserveTier(false, map[string]bool{"vn0": false, "vn1": true, "vn2": false}, 3, 3)

		// This is the series that shows the held-out fix doing its job: vn1 is out of
		// the load balancer because OUR multi-destination verdict put it there, which
		// nothing else in the system records.
		wantHeld := `
# HELP wgfleet_agent_exit_held_out 1 while the master's multi-destination probe is holding this exit out of the wg-best rotation, else 0. Master nodes only.
# TYPE wgfleet_agent_exit_held_out gauge
wgfleet_agent_exit_held_out{exit="vn0",node="master-xa-1",role="master"} 0
wgfleet_agent_exit_held_out{exit="vn1",node="master-xa-1",role="master"} 1
wgfleet_agent_exit_held_out{exit="vn2",node="master-xa-1",role="master"} 0
`
		if err := testutil.GatherAndCompare(reg, strings.NewReader(wantHeld), "wgfleet_agent_exit_held_out"); err != nil {
			t.Error(err)
		}

		wantReserve := `
# HELP wgfleet_agent_reserve_tier_active 1 when wg-best routes to the reserve exit tier (ADR-0029), else 0. Master nodes only.
# TYPE wgfleet_agent_reserve_tier_active gauge
wgfleet_agent_reserve_tier_active{node="master-xa-1",role="master"} 0
`
		if err := testutil.GatherAndCompare(reg, strings.NewReader(wantReserve), "wgfleet_agent_reserve_tier_active"); err != nil {
			t.Error(err)
		}
	})

	t.Run("exit never registers the series", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))
		m.ObserveTier(true, map[string]bool{"vn0": true}, 1, 1) // must be a safe no-op

		for _, name := range []string{
			"wgfleet_agent_exit_held_out",
			"wgfleet_agent_reserve_tier_active",
			"wgfleet_agent_standby_tier_usable",
			"wgfleet_agent_standby_tier_total",
		} {
			if n := testutil.CollectAndCount(reg, name); n != 0 {
				t.Errorf("exit must expose no %s series, got %d", name, n)
			}
		}
	})
}

// An exit that leaves the active tier (drained, or the tier flipped) must stop
// reporting a held-out value rather than freeze at its last one — a stale 1 reads
// as an ongoing outage that nothing will ever clear.
func TestTierMetricsDropExitsThatLeftTheTier(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveTier(false, map[string]bool{"vn0": false, "vn1": true}, 3, 3)
	m.ObserveTier(false, map[string]bool{"vn0": false}, 3, 3)

	want := `
# HELP wgfleet_agent_exit_held_out 1 while the master's multi-destination probe is holding this exit out of the wg-best rotation, else 0. Master nodes only.
# TYPE wgfleet_agent_exit_held_out gauge
wgfleet_agent_exit_held_out{exit="vn0",node="master-xa-1",role="master"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_exit_held_out"); err != nil {
		t.Error(err)
	}
}

// Standby health is the other half of a failover decision: it says whether the
// tier we would move every client onto can reach the internet at all.
func TestTierMetricsRecordStandbyHealth(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveTier(true, map[string]bool{"anz3": false}, 1, 3)

	want := `
# HELP wgfleet_agent_standby_tier_total Exits of the INACTIVE tier that the last warm probe could sample. 0 means the standby has not been measured — a failover would be blind. Master nodes only.
# TYPE wgfleet_agent_standby_tier_total gauge
wgfleet_agent_standby_tier_total{node="master-xa-1",role="master"} 3
# HELP wgfleet_agent_standby_tier_usable Exits of the INACTIVE tier that the last warm probe found usable. Master nodes only.
# TYPE wgfleet_agent_standby_tier_usable gauge
wgfleet_agent_standby_tier_usable{node="master-xa-1",role="master"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"wgfleet_agent_standby_tier_usable", "wgfleet_agent_standby_tier_total"); err != nil {
		t.Error(err)
	}
}

// The standby transport is the path an operator switches an exit onto when the
// active one is blocked — an emergency move. Nothing measured it: on the live
// fleet 2026-09-04 five of six exits had one and none had ever been checked,
// four of them reporting mihomo's untested default of alive=1. This series is
// the difference between "we tested it and it works" and "nobody has ever asked".
func TestStandbyTransportMetricIsMasterOnly(t *testing.T) {
	t.Run("master registers and observes", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
		m.ObserveStandbyTransports(map[StandbyTransport]bool{
			{Exit: "vn0", Transport: "reality-xhttp"}: true,
			{Exit: "1cnode004", Transport: "awg"}:     false,
		})

		want := `
# HELP wgfleet_agent_standby_transport_usable 1 when the last probe found this exit's INACTIVE transport able to reach the internet, 0 when it could not. Absent means never measured, which is not the same as healthy. Master nodes only.
# TYPE wgfleet_agent_standby_transport_usable gauge
wgfleet_agent_standby_transport_usable{exit="1cnode004",node="master-xa-1",role="master",transport="awg"} 0
wgfleet_agent_standby_transport_usable{exit="vn0",node="master-xa-1",role="master",transport="reality-xhttp"} 1
`
		if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_standby_transport_usable"); err != nil {
			t.Error(err)
		}
	})

	t.Run("exit never registers the series", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))
		m.ObserveStandbyTransports(map[StandbyTransport]bool{{Exit: "vn0", Transport: "awg"}: false})
		if n := testutil.CollectAndCount(reg, "wgfleet_agent_standby_transport_usable"); n != 0 {
			t.Errorf("exit must expose no standby_transport series, got %d", n)
		}
	})
}

// An exit that stops having a standby — second transport disabled, or the node
// drained — must drop out of the series. A frozen 0 reads as a fallback that is
// still broken and still needed, and would page forever.
func TestStandbyTransportMetricDropsVanishedExits(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveStandbyTransports(map[StandbyTransport]bool{
		{Exit: "vn0", Transport: "reality-xhttp"}: false,
		{Exit: "vn1", Transport: "reality-xhttp"}: true,
	})
	m.ObserveStandbyTransports(map[StandbyTransport]bool{
		{Exit: "vn1", Transport: "reality-xhttp"}: true,
	})

	want := `
# HELP wgfleet_agent_standby_transport_usable 1 when the last probe found this exit's INACTIVE transport able to reach the internet, 0 when it could not. Absent means never measured, which is not the same as healthy. Master nodes only.
# TYPE wgfleet_agent_standby_transport_usable gauge
wgfleet_agent_standby_transport_usable{exit="vn1",node="master-xa-1",role="master",transport="reality-xhttp"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_standby_transport_usable"); err != nil {
		t.Error(err)
	}
}

// The state gauge must publish EVERY state every pass, not only the current one.
// A gauge that writes just the live state leaves the others frozen at their last
// value, and a dashboard showing "attached" and "gave_up" both true is
// indistinguishable from one whose series simply stopped being written — the
// frozen-green failure this whole metric family exists to avoid.
func TestObserveNetnsMovePublishesEveryState(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveNetnsMove("attached", 1)
	m.ObserveNetnsMove("gave_up", 3)

	if n := testutil.CollectAndCount(reg, "wgfleet_agent_netns_move_state"); n != len(NetnsMoveStates) {
		t.Fatalf("got %d state series, want one per state (%d)", n, len(NetnsMoveStates))
	}
	if got := testutil.ToFloat64(m.netnsMoveState.WithLabelValues("attached")); got != 0 {
		t.Errorf("the state the node left is still reported as current (%v)", got)
	}
	if got := testutil.ToFloat64(m.netnsMoveState.WithLabelValues("gave_up")); got != 1 {
		t.Errorf("the current state is not reported (%v)", got)
	}
	if got := testutil.ToFloat64(m.netnsMoveTries); got != 3 {
		t.Errorf("attempts = %v, want 3", got)
	}
}

// A port that no longer has a socket must stop being reported rather than freeze
// at its last value. The comment in ObserveUDPReturn calls this decisive and
// nothing asserted it.
func TestObserveUDPReturnForgetsPortsThatWentAway(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveUDPReturn(map[int]bool{443: false, 5353: false}, map[int]bool{443: false, 5353: true})
	m.ObserveUDPReturn(map[int]bool{443: false}, map[int]bool{443: false})

	if n := testutil.CollectAndCount(reg, "wgfleet_agent_udp_return_socket"); n != 1 {
		t.Errorf("got %d port series, want only the port that still has a socket", n)
	}
	if got := testutil.ToFloat64(m.udpReturnSocket.WithLabelValues("443")); got != 0 {
		t.Errorf("the live port stopped reporting its black hole (%v)", got)
	}
}

// Same rule for the client-path probes: a probe that stops being taken must
// disappear, not stay green.
func TestObserveClientPathForgetsProbesNoLongerTaken(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveClientPath(map[string]bool{"icmp/gateway": true, "udp/53": true})
	m.ObserveClientPath(map[string]bool{"icmp/gateway": false})

	if n := testutil.CollectAndCount(reg, "wgfleet_agent_client_path_ok"); n != 1 {
		t.Errorf("got %d probe series, want only the probe still being taken", n)
	}
	if got := testutil.ToFloat64(m.clientPathOK.WithLabelValues("icmp/gateway")); got != 0 {
		t.Errorf("the live probe lost its failure (%v)", got)
	}
}

// A mihomo restart is the event that took three exits out of rotation in three
// minutes (an earlier finding) and the only record of it was the master agent's journal.
// The container's start time makes every restart — ours, docker's, a crash — a
// step in one series; the self-heal snapshot says which of them were ours, and
// whether the governor has stopped trying (the same defect with the symptom off).
func TestMihomoStartAndSelfHealAreMasterOnly(t *testing.T) {
	t.Run("exit registers nothing", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))
		m.ObserveMihomoStart(time.Unix(1_700_000_100, 0))
		m.ObserveSelfHeal(map[string]SelfHealStats{"mihomo": {Restarts: 2, Throttled: true}})
		for _, name := range []string{"wgfleet_agent_mihomo_start_time_seconds", "wgfleet_agent_self_heal_restarts", "wgfleet_agent_self_heal_throttled"} {
			if n := testutil.CollectAndCount(reg, name); n != 0 {
				t.Errorf("exit must expose no %s, got %d series", name, n)
			}
		}
	})
	t.Run("master observes", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
		m.ObserveMihomoStart(time.Unix(1_700_000_100, 0))
		m.ObserveSelfHeal(map[string]SelfHealStats{"mihomo": {Restarts: 2, Throttled: true}})
		want := `
# HELP wgfleet_agent_mihomo_start_time_seconds Unix time mihomo's container last started, as docker reports it. Steps forward on every restart — ours, docker's or a crash — so changes() over it is the restart count no single restarter can see. Master nodes only.
# TYPE wgfleet_agent_mihomo_start_time_seconds gauge
wgfleet_agent_mihomo_start_time_seconds{node="master-xa-1",role="master"} 1.7000001e+09
# HELP wgfleet_agent_self_heal_restarts Self-heal restarts the agent has applied to this service since it started (monotonic; read with increase()). Master nodes only.
# TYPE wgfleet_agent_self_heal_restarts gauge
wgfleet_agent_self_heal_restarts{node="master-xa-1",role="master",service="mihomo"} 2
# HELP wgfleet_agent_self_heal_throttled 1 while the restart governor is refusing further self-heal restarts of this service because they keep being needed. The defect is still there; only the symptom is muted. Master nodes only.
# TYPE wgfleet_agent_self_heal_throttled gauge
wgfleet_agent_self_heal_throttled{node="master-xa-1",role="master",service="mihomo"} 1
`
		if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
			"wgfleet_agent_mihomo_start_time_seconds", "wgfleet_agent_self_heal_restarts", "wgfleet_agent_self_heal_throttled"); err != nil {
			t.Error(err)
		}
		// A service that stopped needing restarts long enough for the governor to
		// forget it must drop out rather than freeze at its last value.
		m.ObserveSelfHeal(nil)
		if n := testutil.CollectAndCount(reg, "wgfleet_agent_self_heal_restarts"); n != 0 {
			t.Errorf("forgotten service still reported: %d series", n)
		}
	})
}

// "The standby tier is 2 of 3 usable" is a number nobody can act on: the alert on
// the tally only fires when the LAST reserve member dies, and until then the one
// that is broken has no name anywhere. This series is the name.
func TestStandbyTierMemberMetricNamesTheFailingReserveExit(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))
	m.ObserveStandbyMembers(map[string]bool{"1cnode004": false, "anz3": true})

	want := `
# HELP wgfleet_agent_standby_tier_member_usable 1 when the last warm probe found this member of the INACTIVE exit tier able to reach the internet, 0 when it could not. Absent means never sampled, which is not the same as healthy. Master nodes only.
# TYPE wgfleet_agent_standby_tier_member_usable gauge
wgfleet_agent_standby_tier_member_usable{exit="1cnode004",node="master-xa-1",role="master"} 0
wgfleet_agent_standby_tier_member_usable{exit="anz3",node="master-xa-1",role="master"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_standby_tier_member_usable"); err != nil {
		t.Error(err)
	}

	// An exit that leaves the reserve tier must leave the series with it: a frozen 0
	// pages forever about a fallback nobody is waiting on.
	m.ObserveStandbyMembers(map[string]bool{"anz3": true})
	if n := testutil.CollectAndCount(reg, "wgfleet_agent_standby_tier_member_usable"); n != 1 {
		t.Errorf("the set must be replaced, not merged; got %d series", n)
	}
}

// Renewal is the one thing a node does that can take it off the control plane for
// good, and until now its failures were a log line on the node itself — readable
// only over the channel the failure is about to close. A counter makes a node that
// has been failing to renew visible from outside it, while it can still be reached.
// Rotation happens once in ~9 months, so for almost the whole life of an agent no
// outcome has been observed yet. The failing-renewal alert compares the error series
// against the success series; if neither exists until the first rotation, the rule
// has nothing to evaluate at exactly the moment it was written for.
func TestRenewalSeriesExistBeforeTheFirstRotation(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Now())

	for _, result := range []string{"success", "error"} {
		lbl := map[string]string{"node": "exit-de-1", "role": "exit", "result": result}
		if got := gatherValue(t, reg, "wgfleet_agent_cert_renew_total", lbl); got != 0 {
			t.Errorf("renewals{result=%q} before any rotation = %v, want 0", result, got)
		}
	}
}

func TestRenewalOutcomesAreCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Now())

	m.ObserveCertRenew(nil)
	m.ObserveCertRenew(errors.New("controller refused"))
	m.ObserveCertRenew(errors.New("controller refused"))
	RecordCertReloadError()

	lbl := map[string]string{"node": "exit-de-1", "role": "exit"}
	ok := lbl
	ok["result"] = "success"
	if got := gatherValue(t, reg, "wgfleet_agent_cert_renew_total", ok); got != 1 {
		t.Errorf("successful renewals = %v, want 1", got)
	}
	bad := map[string]string{"node": "exit-de-1", "role": "exit", "result": "error"}
	if got := gatherValue(t, reg, "wgfleet_agent_cert_renew_total", bad); got != 2 {
		t.Errorf("failed renewals = %v, want 2", got)
	}
	if got := gatherValue(t, reg, "wgfleet_agent_cert_reload_errors_total",
		map[string]string{"node": "exit-de-1", "role": "exit"}); got < 1 {
		t.Errorf("reload errors = %v, want at least 1", got)
	}
}

// The reload counter must publish on an EXIT, with no per-pass wiring to forget.
// Its first version was drained once per reconcile pass from inside the agent's
// master-only block, so on every exit — five nodes of six — it stayed at zero
// while the log said the node was one restart from losing the control plane.
// Every node authenticates to the controller with this pair; every node must be
// able to say when it cannot read it.
func TestTheReloadCounterPublishesOnAnExitWithNoWiring(t *testing.T) {
	before := gatherFrom(t, domain.RoleExit)
	RecordCertReloadError()
	if after := gatherFrom(t, domain.RoleExit); after != before+1 {
		t.Errorf("an exit published %v then %v: the failure did not reach the metric", before, after)
	}
}

func gatherFrom(t *testing.T, role domain.Role) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	NewAgentMetrics(reg, "n", role, time.Now())
	return gatherValue(t, reg, "wgfleet_agent_cert_reload_errors_total",
		map[string]string{"node": "n", "role": string(role)})
}

// A hold-out can begin and end between two scrapes; the gauge then never shows
// it, and on 2026-10-26 a master held one exit out for three minutes at a time
// while every rule stayed quiet. The counter counts each hold-out as it begins,
// and every exit in rotation starts at 0 so increase() sees the first one. An
// exit missing from one pass (the tier flipped, or a pass cut short) and back
// still held is the same hold-out, not a new one: counting it again would fire
// WgfleetExitFlapping on an exit that never flapped.
func TestExitHoldoutsAreCountedOnEachEntry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "master-xa-1", domain.RoleMaster, time.Unix(1_700_000_000, 0))

	m.ObserveTier(false, map[string]bool{"vn0": false, "vn1": false}, 3, 3)
	m.ObserveTier(false, map[string]bool{"vn0": true, "vn1": false}, 3, 3)  // vn0 out: 1
	m.ObserveTier(false, map[string]bool{"vn0": true, "vn1": false}, 3, 3)  // still out: no count
	m.ObserveTier(false, map[string]bool{"vn0": false, "vn1": false}, 3, 3) // back
	m.ObserveTier(false, map[string]bool{"vn0": true, "vn1": false}, 3, 3)  // out again: 2
	m.ObserveTier(false, map[string]bool{"vn1": false}, 3, 3)               // vn0 left the tier (tier flip, short pass)
	m.ObserveTier(false, map[string]bool{"vn0": true, "vn1": false}, 3, 3)  // back, still the same hold-out: no count
	m.ObserveTier(false, map[string]bool{"vn0": false, "vn1": false}, 3, 3) // released
	m.ObserveTier(false, map[string]bool{"vn0": true, "vn1": false}, 3, 3)  // out again: 3

	want := `
# HELP wgfleet_agent_exit_holdouts_total Times the master's multi-destination probe took this exit out of the wg-best rotation. Counts hold-outs too short for a scrape of exit_held_out to see. Master nodes only.
# TYPE wgfleet_agent_exit_holdouts_total counter
wgfleet_agent_exit_holdouts_total{exit="vn0",node="master-xa-1",role="master"} 3
wgfleet_agent_exit_holdouts_total{exit="vn1",node="master-xa-1",role="master"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_exit_holdouts_total"); err != nil {
		t.Error(err)
	}
}

func TestExitHoldoutsAreMasterOnly(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "vn0", domain.RoleExit, time.Unix(1_700_000_000, 0))
	m.ObserveTier(false, map[string]bool{"vn0": true}, 1, 1)
	if n := testutil.CollectAndCount(reg, "wgfleet_agent_exit_holdouts_total"); n != 0 {
		t.Errorf("an exit must expose no holdouts series, got %d", n)
	}
}
