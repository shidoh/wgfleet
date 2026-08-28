package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// The dump command must be the one the fleet actually has.
//
// This shelled to `wg show` alone, on the strength of a comment claiming "wg reads
// awg kernel interfaces too, so one command covers both". Measured on a live fleet:
// the master has no `wg` at all (only `awg`), and on an exit `wg show awg0 dump`
// answers "Operation not supported". So `wgfleet_wg_*` was emitted by nobody, on
// any node — and WgfleetNoClientPeers, the one alert that says "your users have
// lost the VPN", could never fire.
func TestWGDumpPrefersAWGThenFallsBackToWG(t *testing.T) {
	var tried []string
	run := func(_ context.Context, bin, iface string) (string, error) {
		tried = append(tried, bin)
		if bin == "awg" {
			return "priv\tpub\t51820\toff\n", nil
		}
		return "", errors.New("wg: command not found")
	}
	out, err := dumpWith(context.Background(), run, "wg0")
	if err != nil {
		t.Fatalf("dump failed even though awg answered: %v", err)
	}
	if out == "" {
		t.Error("awg's output was discarded")
	}
	if len(tried) == 0 || tried[0] != "awg" {
		t.Errorf("tried %v; awg must come first — it is the binary our nodes have", tried)
	}

	// And where only wg exists, it must still work.
	tried = nil
	runWGOnly := func(_ context.Context, bin, iface string) (string, error) {
		tried = append(tried, bin)
		if bin == "wg" {
			return "priv\tpub\t51820\toff\n", nil
		}
		return "", errors.New("awg: command not found")
	}
	if _, err := dumpWith(context.Background(), runWGOnly, "wg0"); err != nil {
		t.Errorf("a wg-only node produced no dump: %v", err)
	}
	if len(tried) != 2 {
		t.Errorf("tried %v, want both binaries attempted", tried)
	}
}

// Absence of the peer series is itself the failure this collector exists to
// report, and absence cannot be alerted on. Emit an explicit reachability gauge
// so "we cannot see the peers" is a signal rather than a silence.
func TestWGCollectorReportsWhenItCannotRead(t *testing.T) {
	reg := prometheus.NewRegistry()
	NewWGCollector(reg, "master-xa-1", "master", []string{"wg0"},
		func(context.Context, string) (string, error) { return "", errors.New("no such tool") })

	got := gatherValue(t, reg, "wgfleet_wg_collector_up", map[string]string{"iface": "wg0"})
	if got != 0 {
		t.Errorf("wgfleet_wg_collector_up = %v, want 0 when the dump cannot be read", got)
	}

	reg2 := prometheus.NewRegistry()
	NewWGCollector(reg2, "master-xa-1", "master", []string{"wg0"},
		func(context.Context, string) (string, error) { return "priv\tpub\t51820\toff\n", nil })
	if got := gatherValue(t, reg2, "wgfleet_wg_collector_up", map[string]string{"iface": "wg0"}); got != 1 {
		t.Errorf("wgfleet_wg_collector_up = %v, want 1 when the dump reads fine", got)
	}
}

// gatherValue pulls one sample's value out of the registry.
func gatherValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			ok := true
			for _, lp := range m.GetLabel() {
				if want, has := labels[lp.GetName()]; has && want != lp.GetValue() {
					ok = false
				}
			}
			if ok {
				if m.GetGauge() != nil {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s%v not found", name, labels)
	return 0
}
