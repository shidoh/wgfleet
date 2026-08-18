package keybroker

import (
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/domain"
)

// TestAWG3EnabledRequiresOptInAndWire is the gate that keeps a premature flip from
// splitting a tunnel. The operator's intent alone is not enough: an exit whose
// agent predates wire v7 drops the 3.0 fields and brings awg0 up as 2.0, while the
// master's mihomo — rendered from this same decision — would emit `version: 3`.
// The two ends would disagree about the wire format, never handshake, and the exit
// would drop out of the load balancer. Degrading to "stays on 2.0" is the only
// acceptable failure mode.
func TestAWG3EnabledRequiresOptInAndWire(t *testing.T) {
	for _, tc := range []struct {
		name  string
		optIn bool
		wire  uint32
		want  bool
	}{
		{"opted in, current agent", true, api.WireAWG3, true},
		{"opted in, newer agent", true, api.WireAWG3 + 1, true},
		{"opted in, agent one version too old", true, api.WireAWG3 - 1, false},
		{"opted in, agent never reported", true, 0, false},
		{"not opted in, current agent", false, api.WireAWG3, false},
		{"not opted in, old agent", false, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := awg3Enabled(tc.optIn, domain.Node{WireVersion: tc.wire})
			if got != tc.want {
				t.Errorf("awg3Enabled(optIn=%v, wire=%d) = %v, want %v", tc.optIn, tc.wire, got, tc.want)
			}
		})
	}
}
