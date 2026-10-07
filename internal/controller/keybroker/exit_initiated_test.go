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
	fleet.Exits[0].Transports.AWG.Enabled = true
	fleet.Exits[0].Transports.AWG.ExitInitiated = true
	fleet.Exits[0].Transports.Reality.Enabled = true
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
	gen, _, err := st.GetAWGPortRotation(context.Background(), eiMaster, eiExit)
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

// Measured on the live fleet 2026-09-30: an exit whose active transport was
// REALITY had its standby AWG rotated every ten minutes — a standby tunnel
// carries no traffic, so a stale handshake there says nothing about the path.
func TestExitInitiatedDoesNotRotateATunnelThatCarriesNothing(t *testing.T) {
	cases := map[string]func(n *domain.Node){
		"reality is the active transport": func(n *domain.Node) { n.ActiveTransport = domain.TransportRealityXHTTP },
		"exit drained":                    func(n *domain.Node) { n.Drain = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			b, st, pub := eiFleet(t, &now)
			ctx := context.Background()
			node, err := st.GetNode(ctx, eiExit)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&node)
			if err := st.UpsertNode(ctx, node); err != nil {
				t.Fatal(err)
			}
			start := now
			report(t, st, eiExit, now, now, eiPinned)
			report(t, st, eiMaster, now, now, "")
			_ = masterTunnel(t, b)
			now = start.Add(AWGRotateAfter + time.Minute)
			report(t, st, eiExit, now, start, eiPinned)
			report(t, st, eiMaster, now, now, "")
			if got := exitPeer(t, b, pub).Endpoint; got != eiPinned {
				t.Fatalf("rotated a tunnel that carries nothing: endpoint %q, want %q", got, eiPinned)
			}
		})
	}
}

// eiTwoMasters is twoMasterFleet with the exit starting its own AWG flow, in the
// given per-tunnel-key phase, and a clock the test moves.
func eiTwoMasters(t *testing.T, phase domain.PerTunnelKeyPhase, clock *time.Time) seededFleet {
	t.Helper()
	fleet := twoMasterFleet()
	fleet.Exits[0].Transports.AWG.ExitInitiated = true
	fleet.Exits[0].PerTunnelKey = string(phase)
	s := seedTwoMasters(t, fleet)
	s.b.now = func() time.Time { return *clock }
	return s
}

func pinnedFor(master, ip string) string {
	return fmt.Sprintf("%s:%d", ip, wg.MasterPortFor(master, "exit-de-1"))
}

// tunnelKeyIn is the key a master dials with in phase — the peer that speaks for
// its tunnel.
func (s seededFleet) tunnelKeyIn(phase domain.PerTunnelKeyPhase, master string) string {
	if phase.MasterUsesPerTunnelKey() {
		return s.tunnelPubs[master]
	}
	return s.sharedPubs[master]
}

func recordExit(t *testing.T, st store.Store, at time.Time, legacy string, peers ...domain.MasterPeerStatus) {
	t.Helper()
	if err := st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: "exit-de-1", State: domain.StateReady, ReportedAt: at, LastHandshake: at,
		AWGMasterEndpoint: legacy, MasterPeers: peers,
	}); err != nil {
		t.Fatal(err)
	}
}

func recordMasters(t *testing.T, st store.Store, at time.Time) {
	t.Helper()
	for _, m := range []string{"master-xa-1", "master-xa-2"} {
		if err := st.RecordStatus(context.Background(), domain.NodeStatus{NodeID: m, State: domain.StateReady, ReportedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
}

func gateOf(t *testing.T, b *Broker, master string) string {
	t.Helper()
	tun, ok := tunnelByName(mustRender(t, b, master).Master.ExitTunnels, "exit-de-1")
	if !ok {
		t.Fatalf("%s renders no AWG tunnel to exit-de-1: there is no gate to read", master)
	}
	return tun.MasterAddr
}

// wantNoTunnel asserts master renders no AWG tunnel to the exit at all — an
// unarmed gate on a tunnel that is not there would prove nothing.
func wantNoTunnel(t *testing.T, b *Broker, master string) {
	t.Helper()
	if tun, ok := tunnelByName(mustRender(t, b, master).Master.ExitTunnels, "exit-de-1"); ok {
		t.Errorf("%s renders an AWG tunnel to exit-de-1 (gate %q), want none", master, tun.MasterAddr)
	}
}

// forgetConfirmations empties the broker's cache of confirmations, as a
// controller restart does; whatever the store holds is read back on the next
// render.
func forgetConfirmations(b *Broker) {
	b.pinMu.Lock()
	defer b.pinMu.Unlock()
	b.pinConfirmed = make(map[string]pinConfirmation)
}

// Each master's gate arms from ITS OWN peer's reported endpoint — the peer that
// carries its traffic in the exit's current phase — and one master's confirmation
// neither arms nor disarms the other's.
func TestEachMasterArmsFromItsOwnPeer(t *testing.T) {
	for _, phase := range []domain.PerTunnelKeyPhase{domain.PerTunnelKeyOff, domain.PerTunnelKeyOn} {
		t.Run(string(phase), func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			s := eiTwoMasters(t, phase, &now)
			pinA, pinB := pinnedFor("master-xa-1", "203.0.113.1"), pinnedFor("master-xa-2", "203.0.113.2")
			keyA, keyB := s.tunnelKeyIn(phase, "master-xa-1"), s.tunnelKeyIn(phase, "master-xa-2")

			exitSpec := mustRender(t, s.b, "exit-de-1")
			pa, _ := peerByKey(exitSpec.Peers, keyA)
			pb, _ := peerByKey(exitSpec.Peers, keyB)
			if pa.Endpoint != pinA || pb.Endpoint != pinB {
				t.Fatalf("exit endpoints = %q, %q; want %q, %q", pa.Endpoint, pb.Endpoint, pinA, pinB)
			}

			// Only master-xa-2's peer holds its pinned address so far.
			recordExit(t, s.st, now, "",
				domain.MasterPeerStatus{PublicKey: keyA, Endpoint: "203.0.113.1:40000"},
				domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB})
			if got := gateOf(t, s.b, "master-xa-1"); got != "" {
				t.Errorf("master-xa-1 armed on %q while its own peer holds another endpoint", got)
			}
			if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
				t.Errorf("master-xa-2 gate = %q, want %q", got, pinB)
			}
			// Now master-xa-1 confirms too; neither confirmation may displace the other.
			recordExit(t, s.st, now, "",
				domain.MasterPeerStatus{PublicKey: keyA, Endpoint: pinA},
				domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB})
			for i := 0; i < 2; i++ {
				if got := gateOf(t, s.b, "master-xa-1"); got != pinA {
					t.Errorf("round %d: master-xa-1 gate = %q, want %q", i, got, pinA)
				}
				if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
					t.Errorf("round %d: master-xa-2 gate = %q, want %q", i, got, pinB)
				}
			}
		})
	}
}

// One master's healthy handshake must not hide another's poisoned flow, one
// master's rotation must not move the other's port — and both rotate when both
// are silent, however their renders interleave.
func TestRotationJudgesAndMovesOneTunnel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	pinA, pinB := pinnedFor("master-xa-1", "203.0.113.1"), pinnedFor("master-xa-2", "203.0.113.2")
	keyA, keyB := s.tunnelKeyIn(phase, "master-xa-1"), s.tunnelKeyIn(phase, "master-xa-2")
	gen := func(master string) int {
		g, _, err := s.st.GetAWGPortRotation(ctx, master, "exit-de-1")
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	report := func(hsA time.Time, epA, epB string) {
		recordExit(t, s.st, now, "",
			domain.MasterPeerStatus{PublicKey: keyA, Endpoint: epA, LastHandshake: hsA},
			domain.MasterPeerStatus{PublicKey: keyB, Endpoint: epB})
		recordMasters(t, s.st, now)
	}
	renderAll := func() {
		for _, id := range []string{"master-xa-1", "master-xa-2", "exit-de-1", "master-xa-2", "master-xa-1"} {
			mustRender(t, s.b, id)
		}
	}

	report(now, pinA, pinB)
	renderAll() // both confirm
	now = now.Add(AWGRotateAfter + time.Minute)
	report(now, pinA, pinB) // master-xa-1 handshakes; master-xa-2 holds its pin and never does
	renderAll()
	if gen("master-xa-2") != 1 {
		t.Errorf("silent tunnel generation = %d, want 1: the other master's handshake masked it", gen("master-xa-2"))
	}
	if gen("master-xa-1") != 0 {
		t.Errorf("healthy tunnel generation = %d, want 0", gen("master-xa-1"))
	}

	// Second round: master-xa-1 goes silent as well, on the address it confirmed.
	silentSince := now
	now = now.Add(AWGRotateAfter + AWGRotateMinInterval + time.Minute)
	report(silentSince, pinA, pinB)
	renderAll()
	if gen("master-xa-1") != 1 {
		t.Errorf("master-xa-1 generation = %d, want 1 once its own tunnel went silent", gen("master-xa-1"))
	}
}

// Review Focus 4. The exit's agent is rolled back below wire 13: it stops sending
// peers. The controller must read it the way it reads any old exit — one
// endpoint, the base master's — not judge the base master on the absence of a
// list it will never get again.
func TestExitRolledBackBelowWire13FallsBackToTheSingleField(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	pinA := pinnedFor("master-xa-1", "203.0.113.1")
	keyA := s.tunnelKeyIn(phase, "master-xa-1")

	recordExit(t, s.st, now, pinA, domain.MasterPeerStatus{PublicKey: keyA, Endpoint: pinA, LastHandshake: now})
	recordMasters(t, s.st, now)
	if got := gateOf(t, s.b, "master-xa-1"); got != pinA {
		t.Fatalf("gate before the rollback = %q, want %q", got, pinA)
	}

	setWireVersion(t, s.st, "exit-de-1", api.WireAWGExitInitiated)
	// The controller restarts too. What it stored is about the wire-13 peer; below
	// wire 13 the single field speaks for the tunnel, and the gate has to hold on
	// that alone.
	forgetConfirmations(s.b)
	for i := 0; i < 3; i++ {
		now = now.Add(AWGRotateAfter)
		recordExit(t, s.st, now, pinA) // wire 12: the single field and a fresh handshake, no peers
		recordMasters(t, s.st, now)
		mustRender(t, s.b, "exit-de-1")
		if got := gateOf(t, s.b, "master-xa-1"); got != pinA {
			t.Fatalf("pass %d after the rollback: gate = %q, want it armed on %q from the single field", i, got, pinA)
		}
		// The single field is not about master-xa-2, and such an exit does not
		// carry it at all.
		wantNoTunnel(t, s.b, "master-xa-2")
	}
	if g, _, _ := s.st.GetAWGPortRotation(ctx, "master-xa-1", "exit-de-1"); g != 0 {
		t.Errorf("a healthy tunnel's port was rotated %d time(s) after the exit was rolled back", g)
	}
}

// A wire-13 exit whose awg0 could not be read this pass sends no peers. That is
// not a silent tunnel: nothing rotates, and a gate already armed stays armed.
func TestAnUnreadablePassRotatesNothing(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	pinB := pinnedFor("master-xa-2", "203.0.113.2")
	keyB := s.tunnelKeyIn(phase, "master-xa-2")

	recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB, LastHandshake: now})
	recordMasters(t, s.st, now)
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("gate = %q, want %q", got, pinB)
	}
	now = now.Add(AWGRotateAfter + time.Minute)
	// A readable status from an unreadable interface: no peers. The single field
	// and the freshest handshake are filled with what would mislead a controller
	// that fell back to them — another address, and a handshake long gone.
	if err := s.st.RecordStatus(ctx, domain.NodeStatus{
		NodeID: "exit-de-1", State: domain.StateReady, ReportedAt: now,
		LastHandshake: now.Add(-2 * AWGRotateAfter), AWGMasterEndpoint: "203.0.113.1:40000",
	}); err != nil {
		t.Fatal(err)
	}
	recordMasters(t, s.st, now)
	mustRender(t, s.b, "exit-de-1")
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Errorf("gate after an unreadable pass = %q, want it still armed", got)
	}
	if g, _, _ := s.st.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1"); g != 0 {
		t.Errorf("port rotated %d time(s) on a pass that could not read the interface", g)
	}
}

// The gate stays armed while the exit roams (see armedMasterAddr), and that
// memory is one tunnel's: with it keyed by the exit alone, the other master's
// next confirmation would overwrite it and disarm a gate nobody disproved.
func TestAnotherMastersConfirmationDoesNotDisarmARoamingTunnel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	pinA, pinB := pinnedFor("master-xa-1", "203.0.113.1"), pinnedFor("master-xa-2", "203.0.113.2")
	keyA, keyB := s.tunnelKeyIn(phase, "master-xa-1"), s.tunnelKeyIn(phase, "master-xa-2")

	recordExit(t, s.st, now, "",
		domain.MasterPeerStatus{PublicKey: keyA, Endpoint: pinA},
		domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB})
	if got := gateOf(t, s.b, "master-xa-1"); got != pinA {
		t.Fatalf("master-xa-1 gate = %q, want %q", got, pinA)
	}
	// master-xa-1's peer roams; master-xa-2's keeps confirming its own address.
	recordExit(t, s.st, now, "",
		domain.MasterPeerStatus{PublicKey: keyA, Endpoint: "203.0.113.1:40000"},
		domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB})
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("master-xa-2 gate = %q, want %q", got, pinB)
	}
	if got := gateOf(t, s.b, "master-xa-1"); got != pinA {
		t.Errorf("master-xa-1 gate = %q after master-xa-2 confirmed, want it still armed on %q", got, pinA)
	}
}

// phaseFlip runs one fleet through a per-tunnel-key phase change on a tunnel
// that has been healthy for longer than AWGRotateAfter. The peer that speaks for
// each tunnel changes with the phase, and the new one has never handshaken — a
// wire-13 exit reports it so from the first pass. That is not a poisoned port:
// the address the exit knocks on has not moved. Nothing rotates and every gate
// stays armed; the new peer then gets a full AWGRotateAfter of its own, after
// which its silence does move the port.
func phaseFlip(t *testing.T, masters int, from, to domain.PerTunnelKeyPhase) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	fleet := twoMasterFleet()
	fleet.Masters = fleet.Masters[:masters]
	fleet.Exits[0].Transports.AWG.ExitInitiated = true
	fleet.Exits[0].PerTunnelKey = string(from)
	s := seedTwoMasters(t, fleet)
	s.b.now = func() time.Time { return now }
	ctx := context.Background()

	pins := map[string]string{}
	for _, m := range fleet.Masters {
		pins[m.Name] = pinnedFor(m.Name, m.PublicIP)
	}
	// report is the exit's status with the peer of `speaking` holding the pinned
	// address and handshaking at hs. The master's other peer is idle — no endpoint,
	// no handshake — unless idleHS says it spoke for the tunnel until then.
	report := func(speaking domain.PerTunnelKeyPhase, hs, idleHS time.Time) {
		t.Helper()
		var peers []domain.MasterPeerStatus
		for _, m := range fleet.Masters {
			spoken := s.tunnelKeyIn(speaking, m.Name)
			idle := s.sharedPubs[m.Name]
			if idle == spoken {
				idle = s.tunnelPubs[m.Name]
			}
			o := domain.MasterPeerStatus{PublicKey: idle}
			if !idleHS.IsZero() {
				o.Endpoint, o.LastHandshake = pins[m.Name], idleHS
			}
			peers = append(peers, domain.MasterPeerStatus{PublicKey: spoken, Endpoint: pins[m.Name], LastHandshake: hs}, o)
			if err := s.st.RecordStatus(ctx, domain.NodeStatus{NodeID: m.Name, State: domain.StateReady, ReportedAt: now}); err != nil {
				t.Fatal(err)
			}
		}
		recordExit(t, s.st, now, "", peers...)
	}
	check := func(when string, wantGen int) {
		t.Helper()
		order := []string{"exit-de-1"}
		for _, m := range fleet.Masters {
			order = append(order, m.Name)
		}
		order = append(order, "exit-de-1")
		for i := len(fleet.Masters) - 1; i >= 0; i-- {
			order = append(order, fleet.Masters[i].Name)
		}
		for _, id := range order {
			mustRender(t, s.b, id)
		}
		for _, m := range fleet.Masters {
			g, _, err := s.st.GetAWGPortRotation(ctx, m.Name, "exit-de-1")
			if err != nil {
				t.Fatal(err)
			}
			if g != wantGen {
				t.Errorf("%s: %s generation = %d, want %d", when, m.Name, g, wantGen)
			}
			if wantGen == 0 {
				if got := gateOf(t, s.b, m.Name); got != pins[m.Name] {
					t.Errorf("%s: %s gate = %q, want it armed on %q", when, m.Name, got, pins[m.Name])
				}
			}
		}
	}

	// A long healthy stretch in the old phase; the other peer is idle.
	report(from, now, time.Time{})
	check("confirmed", 0)
	now = now.Add(AWGRotateAfter + time.Minute)
	report(from, now, time.Time{})
	check("healthy", 0)

	// The flip. The new peer holds the pinned address and has no handshake yet;
	// the old one keeps the endpoint and the handshake it had.
	s.b.fleet.Exits[0].PerTunnelKey = string(to)
	flippedAt := now
	report(to, time.Time{}, flippedAt)
	check("right after the flip", 0)

	now = now.Add(AWGRotateAfter - time.Minute)
	report(to, time.Time{}, flippedAt)
	check("new peer silent for less than the limit", 0)

	now = now.Add(2 * time.Minute)
	report(to, time.Time{}, flippedAt)
	check("new peer silent past the limit", 1)
}

func TestAPhaseChangeDoesNotRotateAHealthyTunnel(t *testing.T) {
	phaseFlip(t, 2, domain.PerTunnelKeyDual, domain.PerTunnelKeySwitch)
}

func TestAPhaseChangeBackDoesNotRotateAHealthyTunnel(t *testing.T) {
	phaseFlip(t, 2, domain.PerTunnelKeySwitch, domain.PerTunnelKeyDual)
}

// A one-master fleet is hit the same way once its exits report per peer.
func TestAPhaseChangeDoesNotRotateAHealthyTunnelOfOneMaster(t *testing.T) {
	phaseFlip(t, 1, domain.PerTunnelKeyDual, domain.PerTunnelKeySwitch)
}

// Stand finding. An exit rolled back below wire 13 stops carrying the non-base
// master; rolled forward, it carries it again. What was confirmed before the gap
// is about a tunnel that then did not exist: judged on that confirmation's age,
// the returning peer — rightly silent, it has only just been put back — looked
// like a poisoned flow and had its port moved on the first render. A pair that is
// not carried has no confirmation; it earns a new one, and its clock, on return.
func TestAPairThatWasNotCarriedConfirmsAfreshOnItsReturn(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	pinA, pinB := pinnedFor("master-xa-1", "203.0.113.1"), pinnedFor("master-xa-2", "203.0.113.2")
	keyA, keyB := s.tunnelKeyIn(phase, "master-xa-1"), s.tunnelKeyIn(phase, "master-xa-2")
	gen := func() int {
		g, _, err := s.st.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1")
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	// wire13 is a report from the exit on the current agent: master-xa-1 healthy,
	// master-xa-2 on its pinned endpoint with the given handshake.
	wire13 := func(hsB time.Time) {
		recordExit(t, s.st, now, "",
			domain.MasterPeerStatus{PublicKey: keyA, Endpoint: pinA, LastHandshake: now},
			domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB, LastHandshake: hsB})
		recordMasters(t, s.st, now)
	}
	renderAll := func() {
		for _, id := range []string{"exit-de-1", "master-xa-1", "master-xa-2"} {
			mustRender(t, s.b, id)
		}
	}

	wire13(now)
	renderAll()
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("gate before the gap = %q, want %q", got, pinB)
	}

	// The gap: the exit's agent goes back below wire 13 and reports one field.
	setWireVersion(t, s.st, "exit-de-1", api.WireAWGExitInitiated)
	renderAll()
	wantNoTunnel(t, s.b, "master-xa-2")
	now = now.Add(AWGRotateAfter + AWGRotateMinInterval + 10*time.Minute)
	recordExit(t, s.st, now, pinA)
	recordMasters(t, s.st, now)
	renderAll()
	if addr, _, _, err := s.st.GetAWGPinConfirmation(ctx, "master-xa-2", "exit-de-1"); err != nil || addr != "" {
		t.Errorf("stored confirmation of the uncarried pair = %q, %v; want none", addr, err)
	}

	// The return: the peer is back on its pinned endpoint and has never handshaken.
	setWireVersion(t, s.st, "exit-de-1", api.WireContractVersion)
	returned := now
	wire13(time.Time{})
	renderAll()
	if gen() != 0 {
		t.Fatalf("generation = %d on the first render after the return, want 0: the port was moved on a confirmation from before the gap", gen())
	}
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Errorf("gate after the return = %q, want it armed on %q from the fresh report", got, pinB)
	}

	// The silence clock runs from the new confirmation.
	now = returned.Add(AWGRotateAfter - time.Minute)
	wire13(time.Time{})
	renderAll()
	if gen() != 0 {
		t.Fatalf("generation = %d before the returned tunnel had been silent for AWGRotateAfter, want 0", gen())
	}
	now = returned.Add(AWGRotateAfter + time.Minute)
	wire13(time.Time{})
	renderAll()
	if gen() != 1 {
		t.Errorf("generation = %d, want 1: a tunnel silent for AWGRotateAfter since it returned is rotated", gen())
	}
}
