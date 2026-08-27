package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/config"
)

func manifestAt(t *testing.T, body string) (path string, eff *config.Effective) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := config.DigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eff = &config.Effective{}
	eff.Set(d)
	return path, eff
}

func TestConfigDriftIsZeroWhenTheFileIsUnchanged(t *testing.T) {
	path, eff := manifestAt(t, "controller:\n  listen: x\n")
	reg := prometheus.NewRegistry()
	NewConfigCollector(reg, path, eff)

	if got := testutil.ToFloat64(driftGauge(t, reg)); got != 0 {
		t.Fatalf("drift = %v, want 0 for an untouched manifest", got)
	}
}

// The signal exists for this: someone edited and walked away without applying.
func TestConfigDriftRisesWhenTheFileIsEdited(t *testing.T) {
	path, eff := manifestAt(t, "controller:\n  listen: x\n")
	reg := prometheus.NewRegistry()
	NewConfigCollector(reg, path, eff)

	if err := os.WriteFile(path, []byte("controller:\n  listen: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(driftGauge(t, reg)); got != 1 {
		t.Fatalf("drift = %v, want 1 after the manifest changed under the controller", got)
	}
}

// The controller rewrites the manifest itself on a transport switch. If that read
// as drift, the signal would cry wolf after every switch and stop being heeded.
func TestConfigDriftClearsAfterTheControllerRecordsItsOwnWrite(t *testing.T) {
	path, eff := manifestAt(t, "controller:\n  listen: x\n")
	reg := prometheus.NewRegistry()
	NewConfigCollector(reg, path, eff)

	if err := os.WriteFile(path, []byte("controller:\n  listen: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := config.DigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	eff.Set(d) // what the controller does after its own write

	if got := testutil.ToFloat64(driftGauge(t, reg)); got != 0 {
		t.Fatalf("drift = %v, want 0 once the controller recorded its own write", got)
	}
}

// Neither 0 nor 1 is honest about a manifest that cannot be read: 0 would assert
// "in sync", 1 would raise an alarm for a cause drift does not describe.
func TestConfigDriftIsAbsentWhenTheManifestCannotBeRead(t *testing.T) {
	path, eff := manifestAt(t, "controller:\n  listen: x\n")
	reg := prometheus.NewRegistry()
	NewConfigCollector(reg, path, eff)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	out := gather(t, reg)
	if strings.Contains(out, "config_drift") {
		t.Errorf("drift was reported for an unreadable manifest:\n%s", out)
	}
	if !strings.Contains(out, "config_info") {
		t.Errorf("the effective digest should still be reported:\n%s", out)
	}
}

func gather(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	var b strings.Builder
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		b.WriteString(mf.GetName())
		b.WriteString("\n")
	}
	return b.String()
}

func driftGauge(t *testing.T, reg *prometheus.Registry) prometheus.Collector {
	t.Helper()
	return driftShim{reg}
}

// driftShim adapts the registry to testutil.ToFloat64, which wants a Collector
// that emits exactly one metric.
type driftShim struct{ reg *prometheus.Registry }

func (d driftShim) Describe(chan<- *prometheus.Desc) {}
func (d driftShim) Collect(ch chan<- prometheus.Metric) {
	mfs, err := d.reg.Gather()
	if err != nil {
		return
	}
	for _, mf := range mfs {
		if !strings.HasSuffix(mf.GetName(), "config_drift") {
			continue
		}
		for _, m := range mf.GetMetric() {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc("drift", "", nil, nil),
				prometheus.GaugeValue, m.GetGauge().GetValue())
		}
	}
}
