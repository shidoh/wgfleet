package metrics

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestUplinkMetricsCountProbesByPeerAndResult(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewUplinkMetrics(reg, "master-xa-1", "master")
	m.ObserveUplinkProbe("master-xa-2", "ok", 45*time.Millisecond)
	m.ObserveUplinkProbe("master-xa-2", "ok", 50*time.Millisecond)
	m.ObserveUplinkProbe("master-xa-2", "slow", 1100*time.Millisecond)
	m.ObserveUplinkProbe("master-xa-2", "fail", 3*time.Second)

	want := `
# HELP wgfleet_agent_uplink_probes_total TCP connects from this master to another master's world-open port, by result: ok, slow (a retransmitted SYN, over 0.9 s), refused (a reset in answer) or fail (no answer).
# TYPE wgfleet_agent_uplink_probes_total counter
wgfleet_agent_uplink_probes_total{node="master-xa-1",peer="master-xa-2",result="fail",role="master"} 1
wgfleet_agent_uplink_probes_total{node="master-xa-1",peer="master-xa-2",result="ok",role="master"} 2
wgfleet_agent_uplink_probes_total{node="master-xa-1",peer="master-xa-2",result="slow",role="master"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_uplink_probes_total"); err != nil {
		t.Fatal(err)
	}
}

// A failed connect has no connect time, only the timeout: it goes to the
// counter and stays out of the histogram, or every outage would read as a
// 3-second connect.
func TestUplinkConnectHistogramSkipsFailures(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewUplinkMetrics(reg, "master-xa-1", "master")
	m.ObserveUplinkProbe("master-xa-2", "ok", 45*time.Millisecond)
	m.ObserveUplinkProbe("master-xa-2", "fail", 3*time.Second)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "wgfleet_agent_uplink_connect_seconds" {
			continue
		}
		if n := mf.GetMetric()[0].GetHistogram().GetSampleCount(); n != 1 {
			t.Fatalf("histogram holds %d samples, want only the successful connect", n)
		}
		return
	}
	t.Fatal("no wgfleet_agent_uplink_connect_seconds series")
}

func TestUplinkMetricsNilSafe(t *testing.T) {
	var m *UplinkMetrics
	m.ObserveUplinkProbe("p", "ok", time.Millisecond) // must not panic
}

// The SYN counters are not drops: they leave wgfleet_fw_drops_total alone and
// come out under their own name with a direction label.
func TestFWCollectorSplitsUplinkCountersFromDrops(t *testing.T) {
	const table = `{"nftables":[
		{"counter":{"family":"inet","name":"scan_drops","table":"wgfleet","packets":42,"bytes":2520}},
		{"counter":{"family":"inet","name":"uplink_syn_out","table":"wgfleet","packets":169,"bytes":10140}},
		{"counter":{"family":"inet","name":"uplink_synack_in","table":"wgfleet","packets":138,"bytes":8280}}
	]}`
	reg := prometheus.NewRegistry()
	NewFWCollector(reg, "master-xa-1", "master", func(context.Context) ([]byte, error) { return []byte(table), nil })

	want := `
# HELP wgfleet_fw_drops_total Packets dropped by a named nftables drop counter in table inet wgfleet.
# TYPE wgfleet_fw_drops_total counter
wgfleet_fw_drops_total{counter="scan_drops",node="master-xa-1",role="master"} 42
# HELP wgfleet_fw_uplink_handshake_packets_total TCP handshake packets crossing this master's public address: syn_out (SYNs it sent, retransmits included) and synack_in (answers it got).
# TYPE wgfleet_fw_uplink_handshake_packets_total counter
wgfleet_fw_uplink_handshake_packets_total{direction="syn_out",node="master-xa-1",role="master"} 169
wgfleet_fw_uplink_handshake_packets_total{direction="synack_in",node="master-xa-1",role="master"} 138
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_fw_drops_total", "wgfleet_fw_uplink_handshake_packets_total"); err != nil {
		t.Fatal(err)
	}
}
