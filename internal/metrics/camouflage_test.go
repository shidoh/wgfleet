package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestCamouflageSeriesFollowTheSite(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAgentMetrics(reg, "exit-de-1", domain.RoleExit, time.Unix(1_700_000_000, 0))
	const own, expiry = "wgfleet_agent_camouflage_target_own", "wgfleet_agent_camouflage_cert_expiry_timestamp_seconds"

	m.ObserveCamouflage("", false, time.Time{})
	if n := testutil.CollectAndCount(reg, own, expiry); n != 0 {
		t.Fatalf("a node without camouflage exposes %d series", n)
	}

	notAfter := time.Unix(1_800_000_000, 0)
	m.ObserveCamouflage("e1.example.net", true, notAfter)
	if v := testutil.ToFloat64(m.camouflageOwn.WithLabelValues("e1.example.net")); v != 1 {
		t.Errorf("target_own = %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.camouflageExpiry.WithLabelValues("e1.example.net")); v != 1_800_000_000 {
		t.Errorf("expiry = %v", v)
	}

	// A new domain replaces the old series instead of leaving it behind.
	m.ObserveCamouflage("e2.example.net", false, time.Time{})
	if n := testutil.CollectAndCount(reg, own); n != 1 {
		t.Errorf("%d target_own series after a domain change, want 1", n)
	}
	if v := testutil.ToFloat64(m.camouflageOwn.WithLabelValues("e2.example.net")); v != 0 {
		t.Errorf("target_own = %v, want 0", v)
	}

	m.ObserveCamouflage("", false, time.Time{})
	if n := testutil.CollectAndCount(reg, own, expiry); n != 0 {
		t.Errorf("camouflage removed, %d series left", n)
	}
}
