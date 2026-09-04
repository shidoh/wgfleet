package metrics

import (
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
