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
