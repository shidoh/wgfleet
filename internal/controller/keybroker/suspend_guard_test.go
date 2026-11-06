package keybroker

import (
	"context"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// A degraded exit is pulled from the balancer only while another exit has been
// measured healthy recently. An exit that has gone quiet, or never measured its
// throughput, proves nothing and must not count as the one that stays.
func TestAutoSuspendCountsOnlyFreshMeasuredExitsAsHealthy(t *testing.T) {
	cases := []struct {
		name  string
		other domain.NodeStatus
	}{
		{"last report is stale", domain.NodeStatus{
			State: domain.StateReady, ReportedAt: time.Date(2026, 9, 7, 8, 0, 0, 0, time.UTC),
			Checks: []domain.HealthCheck{{Name: domain.CheckEgressThroughput, OK: true}},
		}},
		{"throughput never measured", domain.NodeStatus{State: domain.StateReady}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Date(2026, 9, 7, 8, 30, 0, 0, time.UTC)
			b, st, drained := suspendFleet(t, &clock)
			other := tc.other
			other.NodeID = "exit-de-1"
			if other.ReportedAt.IsZero() {
				other.ReportedAt = clock
			}
			if err := st.RecordStatus(context.Background(), other); err != nil {
				t.Fatal(err)
			}
			if drained(b, "exit-de-2") {
				t.Error("exit-de-2 stayed suspended although no other exit is proven healthy")
			}
		})
	}
}
