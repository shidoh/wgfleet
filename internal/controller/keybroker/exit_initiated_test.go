package keybroker

import (
	"context"
	"fmt"
	"testing"

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
