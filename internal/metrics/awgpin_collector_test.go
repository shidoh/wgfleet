package metrics

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func fixtureList(t *testing.T) NFTFunc {
	t.Helper()
	data, err := os.ReadFile("testdata/nft_master_awg_pin.json")
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context) ([]byte, error) { return data, nil }
}

// Captured from nft 1.0.2 on the stand: vn0's tunnel is armed, the exit was heard
// 4 s ago (timeout 60, expires 56), and the forward gate held back 7 packets.
func TestAWGPinCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	names := func(ip string) string {
		if ip == "198.51.100.7" {
			return "vn0"
		}
		return ""
	}
	NewAWGPinCollector(reg, "master-xa-1", "master", fixtureList(t), names)
	want := `
# HELP wgfleet_agent_awg_exit_heard 1 while the exit's knocks on its pinned master port keep it in the gate's heard set, else 0. Master nodes only.
# TYPE wgfleet_agent_awg_exit_heard gauge
wgfleet_agent_awg_exit_heard{exit="vn0",node="master-xa-1",role="master"} 1
# HELP wgfleet_agent_awg_exit_heard_age_seconds Seconds since the exit's last knock on its pinned master port. Absent while the exit is not heard. Master nodes only.
# TYPE wgfleet_agent_awg_exit_heard_age_seconds gauge
wgfleet_agent_awg_exit_heard_age_seconds{exit="vn0",node="master-xa-1",role="master"} 4
# HELP wgfleet_agent_awg_gate_drops_total Packets the master's gate held back from a new flow to the exit because the exit had not knocked yet. Master nodes only.
# TYPE wgfleet_agent_awg_gate_drops_total counter
wgfleet_agent_awg_gate_drops_total{exit="vn0",node="master-xa-1",role="master"} 7
# HELP wgfleet_agent_awg_pin_armed 1 when the master answers this exit's AWG tunnel only from its pinned port and only after hearing the exit (exit-initiated flow). Master nodes only.
# TYPE wgfleet_agent_awg_pin_armed gauge
wgfleet_agent_awg_pin_armed{exit="vn0",node="master-xa-1",role="master"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

// An armed exit the master has not heard is exactly what the alert looks for, so
// it must read as heard=0, not as a missing series.
func TestAWGPinCollectorReportsAnUnheardExit(t *testing.T) {
	data, err := os.ReadFile("testdata/nft_master_awg_pin.json")
	if err != nil {
		t.Fatal(err)
	}
	unheard := strings.Replace(string(data), `, "elem": [{"elem": {"val": "198.51.100.7", "expires": 56}}]`, "", 1)
	reg := prometheus.NewRegistry()
	NewAWGPinCollector(reg, "m", "master", func(context.Context) ([]byte, error) { return []byte(unheard), nil }, nil)
	want := `
# HELP wgfleet_agent_awg_exit_heard 1 while the exit's knocks on its pinned master port keep it in the gate's heard set, else 0. Master nodes only.
# TYPE wgfleet_agent_awg_exit_heard gauge
wgfleet_agent_awg_exit_heard{exit="198.51.100.7",node="m",role="master"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "wgfleet_agent_awg_exit_heard"); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(reg, "wgfleet_agent_awg_exit_heard_age_seconds"); n != 0 {
		t.Fatalf("age series present for an unheard exit: %d", n)
	}
}

func TestAWGPinCollectorSilentWithoutTheTable(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewAWGPinCollector(reg, "m", "master", func(context.Context) ([]byte, error) { return nil, os.ErrNotExist }, nil)
	if n := testutil.CollectAndCount(reg); n != 0 {
		t.Fatalf("unreadable table produced %d series", n)
	}
}
