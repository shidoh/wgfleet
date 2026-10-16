package health

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// `ss -tnH state established` as an exit with the bridge prints it: no state
// column, the peer fourth. Other sockets (SSH, the WARP egress) are noise.
const ssEstablished = `0      0       198.51.100.7:41182   203.0.113.1:48123
0      0       198.51.100.7:22      192.0.2.50:51234
0      36      198.51.100.7:41190   203.0.113.1:48123
0      0       [::ffff:198.51.100.7]:5000 [::ffff:203.0.113.2]:41000
`

func stubSS(out string, err error) runner {
	return func(context.Context, string, ...string) (string, error) { return out, err }
}

func bridgeSpec(portals ...string) domain.NodeSpec {
	var ps []domain.RealityPortalPeer
	for i, a := range portals {
		ps = append(ps, domain.RealityPortalPeer{Master: "m" + string(rune('1'+i)), Address: a})
	}
	return domain.NodeSpec{
		Role:              domain.RoleExit,
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		ActiveTransport:   domain.TransportRealityXHTTP,
		Reality:           &domain.RealityServerSpec{Bridge: &domain.RealityBridgeSpec{Portals: ps}},
	}
}

func TestBridgeConnectionsCountsPerPortal(t *testing.T) {
	got := BridgeConnections(ssEstablished, bridgeSpec("203.0.113.1:48123", "203.0.113.2:41000", "203.0.113.3:40000").Reality.Bridge)
	want := map[string]int{"m1": 2, "m2": 1, "m3": 0}
	for m, n := range want {
		if got[m] != n {
			t.Errorf("connections to %s = %d, want %d (all: %v)", m, got[m], n, got)
		}
	}
}

func TestBridgeProbe(t *testing.T) {
	tests := []struct {
		name     string
		portals  []string
		out      string
		err      error
		wantOK   bool
		wantFrag string
	}{
		{"every portal connected", []string{"203.0.113.1:48123", "203.0.113.2:41000"}, ssEstablished, nil, true, "2/2"},
		// One master down must not mark the exit Degraded: the others carry it.
		{"one portal missing", []string{"203.0.113.1:48123", "203.0.113.9:41000"}, ssEstablished, nil, true, "1/2"},
		{"no portal connected", []string{"203.0.113.8:1", "203.0.113.9:2"}, ssEstablished, nil, false, "no established"},
		{"ss prints nothing", []string{"203.0.113.1:48123"}, "", nil, false, "no established"},
		{"ss fails", []string{"203.0.113.1:48123"}, "", errors.New("exit 1"), false, "ss failed"},
		{"no portals", nil, ssEstablished, nil, false, "no portal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := bridgeSpec(tt.portals...)
			r := bridgeProbeWithRetry(spec.Reality.Bridge, stubSS(tt.out, tt.err), 1, 0)(context.Background())
			if r.OK != tt.wantOK || !strings.Contains(r.Detail, tt.wantFrag) {
				t.Fatalf("probe = %+v, want ok=%v with %q", r, tt.wantOK, tt.wantFrag)
			}
		})
	}
}

// In the mode the exit has no inbound: checking the listening port would fail
// every pass. The bridge check replaces it, and only while REALITY is active.
func TestExitChecksPickTheBridgeCheckInTheMode(t *testing.T) {
	probes := ExitProbes{
		HandshakeFresh: passing("hs"),
		RealityInbound: passing("in"),
		RealityBridge:  passing("br"),
	}
	names := checkNames(ExitChecks(bridgeSpec("203.0.113.1:48123"), probes))
	if !contains(names, "reality-bridge") || contains(names, "reality-inbound") || contains(names, "wg-handshake") {
		t.Errorf("bridge mode, REALITY active: checks = %v", names)
	}

	standby := bridgeSpec("203.0.113.1:48123")
	standby.ActiveTransport = domain.TransportAWG
	names = checkNames(ExitChecks(standby, probes))
	if contains(names, "reality-bridge") || !contains(names, "wg-handshake") {
		t.Errorf("bridge mode, AWG active: checks = %v", names)
	}

	forward := bridgeSpec()
	forward.Reality = &domain.RealityServerSpec{ListenPort: 443}
	names = checkNames(ExitChecks(forward, probes))
	if !contains(names, "reality-inbound") || contains(names, "reality-bridge") {
		t.Errorf("forward mode: checks = %v", names)
	}
}

// A master with a portal reports whether it listens: exits in the mode reach
// this master through nothing else. Not named client-*: the client-path alert
// matches that prefix and is critical.
func TestMasterChecksIncludeThePortalOnlyWhenTheSpecCarriesOne(t *testing.T) {
	probes := MasterProbes{RealityPortalUp: passing("portal")}
	without := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	if contains(checkNames(MasterChecks(without, probes)), "reality-portal") {
		t.Error("portal check without a portal")
	}
	with := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		RealityPortal: &domain.RealityPortalSpec{ListenPort: 48123},
	}}
	if !contains(checkNames(MasterChecks(with, probes)), "reality-portal") {
		t.Error("no portal check with a portal")
	}
}

func TestParseSSEstablishedReadsLastrcv(t *testing.T) {
	socks := ParseSSEstablished("0 0 198.51.100.7:1 203.0.113.1:2\n\t cubic lastsnd:10 lastrcv:31500 lastack:5\n0 0 198.51.100.7:3 203.0.113.1:2\n\t cubic rto:204\n")
	if len(socks) != 2 || !socks[0].HasLastRcv || socks[0].LastRcv != 31500*time.Millisecond || socks[1].HasLastRcv ||
		!socks[0].HasLastAck || socks[0].LastAck != 5*time.Millisecond {
		t.Errorf("sockets = %+v", socks)
	}
}

// The check runs in the pass that may just have restarted xray; the bridge
// needs a moment to dial. It waits a few seconds before failing instead of
// marking the exit Degraded for a whole pass (seen on the stand).
func TestBridgeProbeWaitsForAFreshBridge(t *testing.T) {
	calls := 0
	run := func(context.Context, string, ...string) (string, error) {
		calls++
		if calls < 3 {
			return "", nil
		}
		return ssEstablished, nil
	}
	spec := bridgeSpec("203.0.113.1:48123")
	r := bridgeProbeWithRetry(spec.Reality.Bridge, run, 5, 0)(context.Background())
	if !r.OK || calls != 3 {
		t.Fatalf("probe = %+v after %d calls, want ok on the third", r, calls)
	}
}
