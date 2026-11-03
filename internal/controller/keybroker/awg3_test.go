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
		{"opted in, current agent", true, api.WireAWG3TrackB, true},
		{"opted in, newer agent", true, api.WireAWG3TrackB + 1, true},
		{"opted in, agent one version too old", true, api.WireAWG3TrackB - 1, false},
		{"opted in, agent never reported", true, 0, false},
		{"not opted in, current agent", false, api.WireAWG3TrackB, false},
		{"not opted in, old agent", false, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := awg3Enabled(tc.optIn, domain.Node{WireVersion: tc.wire}, domain.Node{WireVersion: api.WireAWG3TrackB})
			if got != tc.want {
				t.Errorf("awg3Enabled(optIn=%v, wire=%d) = %v, want %v", tc.optIn, tc.wire, got, tc.want)
			}
		})
	}
}

// The gate must consult BOTH ends of the tunnel, not just the exit.
//
// Both call sites passed the EXIT's node record, and the comment beside them said
// the two ends "cannot disagree" because they are decided from the same inputs —
// which was exactly the bug: those inputs described one end. The 3.x parameters on
// the master's side are rendered into mihomo by the MASTER's agent, so a master
// below wire v7 drops them and speaks 2.0 to an exit already on 3.x. And
// rollout.BuildPlan excludes masters by construction, so "exits ahead of the
// master" is the fleet's normal state, not a rare one.
func TestAWG3EnabledRequiresBothEnds(t *testing.T) {
	cur := api.WireAWG3TrackB
	old := api.WireAWG3TrackB - 1
	for _, tc := range []struct {
		name              string
		exitWire, mstWire uint32
		want              bool
	}{
		{"both current", cur, cur, true},
		{"master behind", cur, old, false},
		{"exit behind", old, cur, false},
		{"both behind", old, old, false},
		{"master never reported", cur, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := awg3Enabled(true,
				domain.Node{WireVersion: tc.exitWire},
				domain.Node{WireVersion: tc.mstWire})
			if got != tc.want {
				t.Errorf("awg3Enabled(exit=%d, master=%d) = %v, want %v",
					tc.exitWire, tc.mstWire, got, tc.want)
			}
		})
	}
}
