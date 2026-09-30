package keybroker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

const (
	eiMaster     = "master-xa-1"
	eiExit       = "exit-de-1"
	eiMasterIP   = "203.0.113.1"
	eiMasterMgmt = "10.20.25.254"
)

// eiPinned is the master address the exit must knock on in these tests.
var eiPinned = fmt.Sprintf("%s:%d", eiMasterIP, wg.MasterPortFor(eiMaster, eiExit))

type eiSetup struct {
	phase      domain.PerTunnelKeyPhase
	flag       bool
	masterWire uint32
	exitWire   uint32
	reported   string // the exit's last reported master endpoint
}

// renderExitInitiated seeds one master and one exit, renders both specs and
// returns the exit's peers keyed by public key role plus the master's AWG tunnel.
func renderExitInitiated(t *testing.T, s eiSetup) (legacy, perTunnel domain.PeerSpec, tunnel domain.ExitTunnel) {
	t.Helper()
	fleet := fleetWithPhase(s.phase)
	fleet.Exits[0].Transports.AWG.ExitInitiated = s.flag
	b, st := newBrokerWithFleet(t, fleet)
	ctx := context.Background()

	masterKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	exitKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedNode(t, st, eiMaster, eiMasterMgmt, eiMasterIP, masterKey.PublicKey, domain.RoleMaster)
	seedNode(t, st, eiExit, "10.20.25.1", "198.51.100.1", exitKey.PublicKey, domain.RoleExit)
	perTunnelPub := seedTunnelKey(t, st, eiMaster, eiExit, masterKey.PrivateKey)
	setWireVersion(t, st, eiMaster, s.masterWire)
	setWireVersion(t, st, eiExit, s.exitWire)
	if s.reported != "" {
		recordReported(t, st, s.reported)
	}

	exitSpec, err := b.RenderNodeSpec(ctx, eiExit)
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	legacy, _ = peerByKey(exitSpec.Peers, masterKey.PublicKey)
	perTunnel, _ = peerByKey(exitSpec.Peers, perTunnelPub)

	masterSpec, err := b.RenderNodeSpec(ctx, eiMaster)
	if err != nil {
		t.Fatalf("render master: %v", err)
	}
	for _, et := range masterSpec.Master.ExitTunnels {
		if et.Name == eiExit {
			tunnel = et
		}
	}
	return legacy, perTunnel, tunnel
}

func recordReported(t *testing.T, st store.Store, endpoint string) {
	t.Helper()
	if err := st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: eiExit, State: domain.StateReady, AWGMasterEndpoint: endpoint,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExitInitiatedOffLeavesTheMasterDialing(t *testing.T) {
	legacy, _, tunnel := renderExitInitiated(t, eiSetup{
		phase: domain.PerTunnelKeyOff, masterWire: api.WireAWGExitInitiated, exitWire: api.WireAWGExitInitiated,
	})
	if legacy.Endpoint != "" {
		t.Errorf("flag off: exit's master peer endpoint = %q, want empty", legacy.Endpoint)
	}
	if tunnel.MasterAddr != "" {
		t.Errorf("flag off: master tunnel MasterAddr = %q, want empty", tunnel.MasterAddr)
	}
}

// Either end below wire 12 cannot hold its half: an old master keeps opening the
// flow from a random port, an old exit never reports the endpoint back.
func TestExitInitiatedNeedsBothEndsOnTheNewWire(t *testing.T) {
	cases := map[string]eiSetup{
		"old master": {masterWire: api.WireAWGExitInitiated - 1, exitWire: api.WireAWGExitInitiated},
		"old exit":   {masterWire: api.WireAWGExitInitiated, exitWire: api.WireAWGExitInitiated - 1},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			s.phase, s.flag, s.reported = domain.PerTunnelKeyOff, true, eiPinned
			legacy, _, tunnel := renderExitInitiated(t, s)
			if legacy.Endpoint != "" || tunnel.MasterAddr != "" {
				t.Fatalf("endpoint %q / MasterAddr %q rendered with an end below wire %d",
					legacy.Endpoint, tunnel.MasterAddr, api.WireAWGExitInitiated)
			}
		})
	}
}

// The endpoint goes on the peer the master actually dials with, and only there:
// the other identity has no master behind it, and its handshakes would be noise
// on the same tuple.
func TestExitInitiatedEndpointFollowsTheMastersIdentity(t *testing.T) {
	tests := []struct {
		phase         domain.PerTunnelKeyPhase
		wantOnPerTun  bool
		wantOnLegacy  bool
		legacyPresent bool
	}{
		{domain.PerTunnelKeyOff, false, true, true},
		{domain.PerTunnelKeyDual, false, true, true},
		{domain.PerTunnelKeySwitch, true, false, true},
		{domain.PerTunnelKeyOn, true, false, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.phase), func(t *testing.T) {
			legacy, perTun, _ := renderExitInitiated(t, eiSetup{
				phase: tc.phase, flag: true,
				masterWire: api.WireAWGExitInitiated, exitWire: api.WireAWGExitInitiated,
			})
			if got := legacy.Endpoint == eiPinned; got != tc.wantOnLegacy {
				t.Errorf("legacy peer endpoint = %q, want pinned: %v", legacy.Endpoint, tc.wantOnLegacy)
			}
			if tc.legacyPresent && !tc.wantOnLegacy && legacy.Endpoint != "" {
				t.Errorf("legacy peer endpoint = %q, want empty", legacy.Endpoint)
			}
			if got := perTun.Endpoint == eiPinned; got != tc.wantOnPerTun {
				t.Errorf("per-tunnel peer endpoint = %q, want pinned: %v", perTun.Endpoint, tc.wantOnPerTun)
			}
		})
	}
}

// The master's gate is armed only once the exit says it holds the pinned
// endpoint: a gate armed ahead of that is a master that stops answering an exit
// still knocking somewhere else — the partial-rollout outage.
func TestExitInitiatedArmsTheGateOnlyAfterTheExitConfirms(t *testing.T) {
	cases := map[string]struct {
		reported string
		want     string
	}{
		"exit has not reported":         {"", ""},
		"exit holds another endpoint":   {eiMasterIP + ":40000", ""},
		"exit holds the pinned address": {eiPinned, eiPinned},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, tunnel := renderExitInitiated(t, eiSetup{
				phase: domain.PerTunnelKeyOff, flag: true, reported: tc.reported,
				masterWire: api.WireAWGExitInitiated, exitWire: api.WireAWGExitInitiated,
			})
			if tunnel.MasterAddr != tc.want {
				t.Fatalf("MasterAddr = %q, want %q", tunnel.MasterAddr, tc.want)
			}
		})
	}
}

func TestExitInitiatedHonoursThePortOverride(t *testing.T) {
	fleet := fleetWithPhase(domain.PerTunnelKeyOff)
	fleet.Exits[0].Transports.AWG.ExitInitiated = true
	fleet.Exits[0].Transports.AWG.MasterPort = 41234
	b, st := newBrokerWithFleet(t, fleet)
	masterKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedNode(t, st, eiMaster, eiMasterMgmt, eiMasterIP, masterKey.PublicKey, domain.RoleMaster)
	seedNode(t, st, eiExit, "10.20.25.1", "198.51.100.1", "", domain.RoleExit)
	setWireVersion(t, st, eiMaster, api.WireAWGExitInitiated)
	setWireVersion(t, st, eiExit, api.WireAWGExitInitiated)

	spec, err := b.RenderNodeSpec(context.Background(), eiExit)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := peerByKey(spec.Peers, masterKey.PublicKey)
	if legacy.Endpoint != eiMasterIP+":41234" {
		t.Fatalf("endpoint = %q, want %s:41234", legacy.Endpoint, eiMasterIP)
	}
}

// A master known only by a private address (the management overlay) is one the
// exit cannot knock on from the internet; rendering the endpoint anyway would
// hand the exit a dead address and, once armed, a gate that never opens.
func TestExitInitiatedRefusesAMasterWithoutAPublicAddress(t *testing.T) {
	fleet := fleetWithPhase(domain.PerTunnelKeyOff)
	fleet.Exits[0].Transports.AWG.ExitInitiated = true
	b, st := newBrokerWithFleet(t, fleet)
	masterKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedNode(t, st, eiMaster, eiMasterMgmt, "172.16.99.10", masterKey.PublicKey, domain.RoleMaster)
	seedNode(t, st, eiExit, "10.20.25.1", "198.51.100.1", "", domain.RoleExit)
	setWireVersion(t, st, eiMaster, api.WireAWGExitInitiated)
	setWireVersion(t, st, eiExit, api.WireAWGExitInitiated)

	spec, err := b.RenderNodeSpec(context.Background(), eiExit)
	if err != nil {
		t.Fatal(err)
	}
	if legacy, _ := peerByKey(spec.Peers, masterKey.PublicKey); legacy.Endpoint != "" {
		t.Fatalf("endpoint = %q rendered for a master with only a private address", legacy.Endpoint)
	}
}

// eiFleet is the one-master, one-exit fleet with the flag on and a clock the test
// moves, seeded at wire 12 on both ends.
func eiFleet(t *testing.T, clock *time.Time) (*Broker, store.Store, string) {
	t.Helper()
	fleet := fleetWithPhase(domain.PerTunnelKeyOff)
	fleet.Exits[0].Transports.AWG.ExitInitiated = true
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	b := New(st, fleet, slog.New(slog.NewTextHandler(io.Discard, nil)), WithClock(func() time.Time { return *clock }))
	masterKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	exitKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedNode(t, st, eiMaster, eiMasterMgmt, eiMasterIP, masterKey.PublicKey, domain.RoleMaster)
	seedNode(t, st, eiExit, "10.20.25.1", "198.51.100.1", exitKey.PublicKey, domain.RoleExit)
	setWireVersion(t, st, eiMaster, api.WireAWGExitInitiated)
	setWireVersion(t, st, eiExit, api.WireAWGExitInitiated)
	return b, st, masterKey.PublicKey
}

func report(t *testing.T, st store.Store, node string, at, handshake time.Time, endpoint string) {
	t.Helper()
	if err := st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: node, State: domain.StateReady, ReportedAt: at, LastHandshake: handshake, AWGMasterEndpoint: endpoint,
	}); err != nil {
		t.Fatal(err)
	}
}

func masterTunnel(t *testing.T, b *Broker) domain.ExitTunnel {
	t.Helper()
	spec, err := b.RenderNodeSpec(context.Background(), eiMaster)
	if err != nil {
		t.Fatal(err)
	}
	for _, et := range spec.Master.ExitTunnels {
		if et.Name == eiExit {
			return et
		}
	}
	t.Fatal("no tunnel for the exit")
	return domain.ExitTunnel{}
}

func exitPeer(t *testing.T, b *Broker, masterPub string) domain.PeerSpec {
	t.Helper()
	spec, err := b.RenderNodeSpec(context.Background(), eiExit)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := peerByKey(spec.Peers, masterPub)
	return p
}

// Once the exit has confirmed the pinned address, a report of another endpoint
// is WireGuard roaming, which the exit's own watchdog undoes within a pass.
// Disarming on it flapped the gate on the stand while a port changed.
func TestExitInitiatedStaysArmedWhileTheExitRoams(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, _ := eiFleet(t, &now)
	report(t, st, eiExit, now, now, eiPinned)
	if got := masterTunnel(t, b).MasterAddr; got != eiPinned {
		t.Fatalf("not armed after confirmation: %q", got)
	}
	report(t, st, eiExit, now, now, eiMasterIP+":40000")
	if got := masterTunnel(t, b).MasterAddr; got != eiPinned {
		t.Fatalf("disarmed on a roamed report: %q", got)
	}
}

// The exit speaks often enough that a path filter never sees the flow idle.
func TestExitInitiatedPeerKeepsTheFlowBusy(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, _, pub := eiFleet(t, &now)
	if k := exitPeer(t, b, pub).Keepalive; k < 5 || k > 9 {
		t.Fatalf("exit-initiated peer keepalive = %d, want 5-9 s", k)
	}
}

// Measured on the stand: a pinned flow the filter poisoned or froze never comes
// back — every keepalive keeps the bad state alive. Only a new port helps, and
// the exit then opens the new flow itself.
func TestExitInitiatedRotatesAStaleTunnel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, pub := eiFleet(t, &now)
	start := now
	report(t, st, eiExit, now, now, eiPinned)
	report(t, st, eiMaster, now, now, "")
	_ = masterTunnel(t, b) // confirmation seen

	now = start.Add(AWGRotateAfter + time.Minute)
	report(t, st, eiExit, now, start, eiPinned) // alive, reporting, handshake stale
	report(t, st, eiMaster, now, now, "")
	rotated := fmt.Sprintf("%s:%d", eiMasterIP, wg.MasterPortForGen(eiMaster, eiExit, 1))
	if got := exitPeer(t, b, pub).Endpoint; got != rotated {
		t.Fatalf("stale tunnel not rotated: endpoint %q, want %q", got, rotated)
	}
	// The new address needs its own confirmation before the gate arms on it.
	if got := masterTunnel(t, b).MasterAddr; got != "" {
		t.Fatalf("armed on the new port before the exit confirmed it: %q", got)
	}
	// One rotation per interval, however many renders come in between.
	if got := exitPeer(t, b, pub).Endpoint; got != rotated {
		t.Fatalf("rotated twice in one interval: %q", got)
	}
	gen, _, err := st.GetAWGPortRotation(context.Background(), eiExit)
	if err != nil || gen != 1 {
		t.Fatalf("generation = %d (%v), want 1", gen, err)
	}
}

func TestExitInitiatedLeavesHealthyAndSilentTunnelsAlone(t *testing.T) {
	cases := map[string]func(start, now time.Time, st store.Store){
		"handshake fresh": func(start, now time.Time, st store.Store) {
			report(t, st, eiExit, now, now, eiPinned)
			report(t, st, eiMaster, now, now, "")
		},
		// A silent exit is down, not filtered: a new port would not help, and the
		// operator's alerts cover a node that stopped reporting.
		"exit not reporting": func(start, now time.Time, st store.Store) {
			report(t, st, eiExit, start, start, eiPinned)
			report(t, st, eiMaster, now, now, "")
		},
		"master not reporting": func(start, now time.Time, st store.Store) {
			report(t, st, eiExit, now, start, eiPinned)
			report(t, st, eiMaster, start, start, "")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			b, st, pub := eiFleet(t, &now)
			start := now
			report(t, st, eiExit, now, now, eiPinned)
			report(t, st, eiMaster, now, now, "")
			_ = masterTunnel(t, b)
			now = start.Add(AWGRotateAfter + time.Minute)
			setup(start, now, st)
			if got := exitPeer(t, b, pub).Endpoint; got != eiPinned {
				t.Fatalf("rotated: endpoint %q, want %q", got, eiPinned)
			}
		})
	}
}
