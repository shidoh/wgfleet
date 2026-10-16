package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func bridgeReg(t *testing.T, conns map[string]int, err error, kills map[string]uint64) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	NewBridgeCollector(reg, "exit-1", "exit",
		func(context.Context) (map[string]int, error) { return conns, err },
		func() map[string]uint64 { return kills })
	return reg
}

const bridgeHelp = `
# HELP wgfleet_agent_reality_bridge_connected 1 when the exit's reality bridge holds an established connection to this master's portal, 0 when it holds none. Absent outside the exit-initiated REALITY mode.
# TYPE wgfleet_agent_reality_bridge_connected gauge
`

const killsHelp = `
# HELP wgfleet_agent_reality_bridge_kills_total Bridge sockets to this master's portal the watchdog killed because they received nothing for 30 s — one-way freezes on that path.
# TYPE wgfleet_agent_reality_bridge_kills_total counter
`

func TestBridgeCollectorPerMaster(t *testing.T) {
	reg := bridgeReg(t, map[string]int{"xa-1": 3, "xa-2": 0}, nil, map[string]uint64{"xa-2": 4})
	want := bridgeHelp + `wgfleet_agent_reality_bridge_connected{master="xa-1",node="exit-1",role="exit"} 1
wgfleet_agent_reality_bridge_connected{master="xa-2",node="exit-1",role="exit"} 0
` + killsHelp + `wgfleet_agent_reality_bridge_kills_total{master="xa-1",node="exit-1",role="exit"} 0
wgfleet_agent_reality_bridge_kills_total{master="xa-2",node="exit-1",role="exit"} 4
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

// Outside the mode (no portals) the collector says nothing, so no alert can fire
// on an exit that was never meant to dial.
func TestBridgeCollectorSilentOutsideTheMode(t *testing.T) {
	reg := bridgeReg(t, nil, nil, nil)
	if n, err := testutil.GatherAndCount(reg); err != nil || n != 0 {
		t.Errorf("series = %d, %v; want none", n, err)
	}
}

// A failed read must not report every master disconnected.
func TestBridgeCollectorReadErrorEmitsNoConnectedSeries(t *testing.T) {
	reg := bridgeReg(t, map[string]int{"xa-1": 0}, errors.New("ss failed"), map[string]uint64{"xa-1": 1})
	if n, _ := testutil.GatherAndCount(reg, "wgfleet_agent_reality_bridge_connected"); n != 0 {
		t.Errorf("connected series on a read error: %d", n)
	}
}
