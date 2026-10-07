package keybroker

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// twoMasterFleet is testFleet with a second master in slot 1, under an anchor
// label that is the base master's name — what an operator gets by following the
// validation message when adding a master to a one-master fleet.
func twoMasterFleet() config.FleetSection {
	f := testFleet()
	on := true
	f.AWG3 = &on
	f.InterfaceAnchor = "master-xa-1"
	f.Masters[0].PublicIP = "203.0.113.1"
	f.Exits[0].PublicIP = "198.51.100.1"
	f.Exits[0].Transports.AWG.Enabled = true
	f.Exits[0].Transports.Reality.Enabled = true
	f.Masters = append(f.Masters, config.MasterConfig{
		Name: "master-xa-2", Slot: 1, MgmtAddr: "10.20.25.253", PublicIP: "203.0.113.2",
		ClientAWG: config.ClientAWGConfig{ListenPort: 443, AddressPool: "10.90.0.0/24"},
		Routing:   config.MasterRouting{DirectCIDRs: []string{"172.16.0.0/12"}, Balance: "health"},
	})
	return f
}

type seededFleet struct {
	b          *Broker
	st         store.Store
	sharedPubs map[string]string // master → its shared public key
	tunnelPubs map[string]string // master → its per-tunnel public key for exit-de-1
}

// seedTwoMasters registers every master of fleet and its first exit at the
// current wire version.
func seedTwoMasters(t *testing.T, fleet config.FleetSection) seededFleet {
	t.Helper()
	b, st := newBrokerWithFleet(t, fleet)
	out := seededFleet{b: b, st: st, sharedPubs: map[string]string{}, tunnelPubs: map[string]string{}}
	e := fleet.Exits[0]
	for _, m := range fleet.Masters {
		kp, err := wg.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		seedNode(t, st, m.Name, m.MgmtAddr, m.PublicIP, kp.PublicKey, domain.RoleMaster)
		setWireVersion(t, st, m.Name, api.WireContractVersion)
		out.sharedPubs[m.Name] = kp.PublicKey
		out.tunnelPubs[m.Name] = seedTunnelKey(t, st, m.Name, e.Name, kp.PrivateKey)
	}
	exitKey, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	seedNode(t, st, e.Name, "10.20.25.1", e.PublicIP, exitKey.PublicKey, domain.RoleExit)
	setWireVersion(t, st, e.Name, api.WireContractVersion)
	if err := st.SetNodeRealityKey(context.Background(), e.Name, goldenRealityPub); err != nil {
		t.Fatal(err)
	}
	return out
}

func mustRender(t *testing.T, b *Broker, id string) domain.NodeSpec {
	t.Helper()
	spec, err := b.RenderNodeSpec(context.Background(), id)
	if err != nil {
		t.Fatalf("render %s: %v", id, err)
	}
	return spec
}

// RED before this task. Whatever master renders, the exit's interface and that
// master's end of the tunnel must carry the same shared AmneziaWG parameters and
// the same REALITY identifiers — or no handshake completes.
func TestBothEndsAgreeOnTheExitInterface(t *testing.T) {
	for _, anchor := range []string{"master-xa-1", "a-label-no-master-carries"} {
		fleet := twoMasterFleet()
		fleet.InterfaceAnchor = anchor
		s := seedTwoMasters(t, fleet)
		exitSpec := mustRender(t, s.b, "exit-de-1")
		for _, m := range fleet.Masters {
			spec := mustRender(t, s.b, m.Name)
			tun, ok := tunnelByName(spec.Master.ExitTunnels, "exit-de-1")
			if !ok {
				t.Fatalf("anchor=%s master %s: no AWG tunnel", anchor, m.Name)
			}
			if !reflect.DeepEqual(tun.AWG.Shared, exitSpec.WGServer.AWG.Shared) {
				t.Errorf("anchor=%s master %s: shared AWG params differ from the exit interface", anchor, m.Name)
			}
			rt, ok := tunnelByName(spec.Master.ExitTunnels, "exit-de-1-reality")
			if !ok {
				t.Fatalf("anchor=%s master %s: no reality tunnel", anchor, m.Name)
			}
			if rt.Reality.UUID != exitSpec.Reality.UUID || rt.Reality.ShortID != exitSpec.Reality.ShortID {
				t.Errorf("anchor=%s master %s: REALITY ids differ from the exit inbound", anchor, m.Name)
			}
		}
	}
}

// RED before this task. A master that has reported and is too old for AmneziaWG
// 3.0 takes the whole interface to 2.0 — on every end at once, never split.
func TestAnOldMasterTakesEveryEndToAWG2(t *testing.T) {
	fleet := twoMasterFleet()
	s := seedTwoMasters(t, fleet)
	setWireVersion(t, s.st, "master-xa-2", api.WireAWG3-1)
	if mustRender(t, s.b, "exit-de-1").WGServer.AWG.AWG3Enabled() {
		t.Fatal("the exit interface kept 3.0 with a master that cannot speak it")
	}
	for _, m := range fleet.Masters {
		tun, _ := tunnelByName(mustRender(t, s.b, m.Name).Master.ExitTunnels, "exit-de-1")
		if tun.AWG.AWG3Enabled() {
			t.Errorf("master %s renders 3.0 against a 2.0 exit interface", m.Name)
		}
	}
}

// RED before this task. A master with no record in the store — not deployed yet,
// or dead and cleaned out — has no say in the generation. Reading its absence as
// "wire 0, too old" would drop a working fleet to 2.0 and restart awg0 on every
// exit, both when an operator writes a master in and when one is buried.
func TestAMasterWithoutARecordHasNoSayInTheGeneration(t *testing.T) {
	one := twoMasterFleet()
	one.Masters = one.Masters[:1]
	s := seedTwoMasters(t, one) // master-xa-2 never registers
	b := New(s.st, twoMasterFleet(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !mustRender(t, b, "exit-de-1").WGServer.AWG.AWG3Enabled() {
		t.Error("AmneziaWG 3.0 was dropped for a master that has never reported")
	}
}

// Guard (green before and after; falsified in Step 5). The ends may — and so
// must — differ in what AmneziaWG lets differ.
func TestNonBaseMasterGetsItsOwnLocalDecoy(t *testing.T) {
	s := seedTwoMasters(t, twoMasterFleet())
	ta, _ := tunnelByName(mustRender(t, s.b, "master-xa-1").Master.ExitTunnels, "exit-de-1")
	tb, _ := tunnelByName(mustRender(t, s.b, "master-xa-2").Master.ExitTunnels, "exit-de-1")
	if reflect.DeepEqual(ta.AWG.Local, tb.AWG.Local) {
		t.Error("both masters render the same local decoy profile")
	}
}
