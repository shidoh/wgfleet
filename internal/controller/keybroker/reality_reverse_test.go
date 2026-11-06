package keybroker

import (
	"bytes"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// reverseFleet is two masters with public addresses and one dual-transport exit
// in the exit-initiated REALITY mode.
func reverseFleet() config.FleetSection {
	f := testFleet()
	f.Masters[0].PublicIP = "203.0.113.1"
	m2 := f.Masters[0]
	m2.Name, m2.Slot, m2.PublicIP, m2.MgmtAddr = "master-xa-2", 1, "203.0.113.2", "10.20.25.253"
	// Listed out of slot order on purpose: the bridge dials by slot.
	f.Masters = []config.MasterConfig{m2, f.Masters[0]}
	f.InterfaceAnchor = "master-xa-1"
	f.Exits[0].Transports = config.TransportsConfig{
		AWG:     config.AWGTransportConfig{Enabled: true},
		Reality: config.RealityTransportConfig{Enabled: true, ExitInitiated: true},
	}
	return f
}

type reverseSetup struct {
	b    *Broker
	st   store.Store
	logs *bytes.Buffer
	pubs map[string]string
}

// newReverseSetup seeds both masters and the exit on wire 14, each master with a
// published portal key.
func newReverseSetup(t *testing.T) reverseSetup {
	t.Helper()
	b, st := newBrokerWithFleet(t, reverseFleet())
	var logs bytes.Buffer
	b.log = slog.New(slog.NewTextHandler(&logs, nil))
	s := reverseSetup{b: b, st: st, logs: &logs, pubs: map[string]string{}}
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "master-xa-2", "10.20.25.253", "203.0.113.2", "/Lpxg7UgcxjrQcfYYl9CaqXDLy/bYSHQ3iD/KXnY1zU=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	for _, id := range []string{"master-xa-1", "master-xa-2", "exit-de-1"} {
		setWireVersion(t, st, id, api.WireRealityReverse)
	}
	for _, m := range []string{"master-xa-1", "master-xa-2"} {
		_, pub, err := xray.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetNodeRealityPortalKey(context.Background(), m, pub); err != nil {
			t.Fatal(err)
		}
		s.pubs[m] = pub
	}
	return s
}

func (s reverseSetup) exit(t *testing.T) (config.ExitConfig, domain.Node) {
	t.Helper()
	n, err := s.st.GetNode(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	return s.b.fleet.Exits[0], n
}

func portalMasters(ps []portalTarget) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Master.Name)
	}
	return out
}

func TestRealityReverseIsOnWhenFlagAndExitWireAgree(t *testing.T) {
	s := newReverseSetup(t)
	exit, node := s.exit(t)
	if !s.b.realityReverse(exit, node) {
		t.Fatal("exit with the flag on wire 14 is not in the mode")
	}
}

func TestRealityReverseOffWithoutTheFlagOrReality(t *testing.T) {
	s := newReverseSetup(t)
	exit, node := s.exit(t)
	off := exit
	off.Transports.Reality.ExitInitiated = false
	if s.b.realityReverse(off, node) {
		t.Error("the mode is on without the flag")
	}
	noReality := exit
	noReality.Transports.Reality.Enabled = false
	if s.b.realityReverse(noReality, node) {
		t.Error("the mode is on with REALITY disabled")
	}
}

// An exit agent below wire 14 would drop the bridge and open nothing: it stays
// in forward REALITY, and the operator hears it once, not every pass.
func TestRealityReverseOffForAnOldExitWarnsOnce(t *testing.T) {
	s := newReverseSetup(t)
	setWireVersion(t, s.st, "exit-de-1", api.WireRealityReverse-1)
	exit, node := s.exit(t)
	for range 3 {
		if s.b.realityReverse(exit, node) {
			t.Fatal("the mode is on for a wire-13 exit")
		}
	}
	if n := strings.Count(s.logs.String(), "exit-initiated REALITY"); n != 1 {
		t.Fatalf("warned %d times, want once:\n%s", n, s.logs.String())
	}
}

func TestPortalTargetsListsReadyMastersBySlot(t *testing.T) {
	s := newReverseSetup(t)
	exit, _ := s.exit(t)
	ps, err := s.b.portalTargets(context.Background(), exit)
	if err != nil {
		t.Fatal(err)
	}
	if got := portalMasters(ps); strings.Join(got, ",") != "master-xa-1,master-xa-2" {
		t.Fatalf("portals = %v, want both by slot", got)
	}
	m1 := ps[0]
	want := s.b.fleet.Masters[1].RealityPortalListenPort()
	if m1.Addr.String() != "203.0.113.1:"+strconv.Itoa(want) || m1.PublicKey != s.pubs["master-xa-1"] {
		t.Errorf("master-xa-1 portal = %+v, want 203.0.113.1:%d with its key", m1, want)
	}
}

// One master not ready costs only its own tunnel to the exit (D8): the others
// keep theirs, and the operator hears why once.
func TestPortalTargetsSkipsAMasterThatIsNotReady(t *testing.T) {
	cases := map[string]func(t *testing.T, s reverseSetup){
		"wire 13": func(t *testing.T, s reverseSetup) {
			setWireVersion(t, s.st, "master-xa-2", api.WireRealityReverse-1)
		},
		"no portal key": func(t *testing.T, s reverseSetup) {
			if err := s.st.SetNodeRealityPortalKey(context.Background(), "master-xa-2", ""); err != nil {
				t.Fatal(err)
			}
		},
		"private address": func(t *testing.T, s reverseSetup) {
			s.b.fleet.Masters[0].PublicIP = "10.0.0.2"
			node, _ := s.st.GetNode(context.Background(), "master-xa-2")
			node.PublicIP = "10.0.0.2"
			if err := s.st.UpsertNode(context.Background(), node); err != nil {
				t.Fatal(err)
			}
		},
		"never registered": func(t *testing.T, s reverseSetup) {
			if err := s.st.DeleteNode(context.Background(), "master-xa-2"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := newReverseSetup(t)
			mutate(t, s)
			exit, _ := s.exit(t)
			for range 2 {
				ps, err := s.b.portalTargets(context.Background(), exit)
				if err != nil {
					t.Fatal(err)
				}
				if got := portalMasters(ps); strings.Join(got, ",") != "master-xa-1" {
					t.Fatalf("portals = %v, want master-xa-1 only", got)
				}
			}
			if n := strings.Count(s.logs.String(), "master-xa-2"); n != 1 {
				t.Errorf("master-xa-2 named %d times in the log, want once:\n%s", n, s.logs.String())
			}
		})
	}
}

// The pair's identity is a secret the controller minted, not a function of
// names: an exit that could compute another exit's bridge UUID could register
// under its reverse tag and receive its client streams.
func TestPortalIDsAreRandomStableAndPerPair(t *testing.T) {
	s := newReverseSetup(t)
	ctx := context.Background()
	ids := func(b *Broker, exit, master string) (string, string) {
		t.Helper()
		u, sid, err := b.portalIDs(ctx, exit, master)
		if err != nil {
			t.Fatal(err)
		}
		if len(sid) != 16 {
			t.Errorf("short-id %q, want 8 random bytes", sid)
		}
		return u, sid
	}
	u1, s1 := ids(s.b, "exit-de-1", "master-xa-1")
	u2, s2 := ids(s.b, "exit-de-1", "master-xa-2")
	u3, _ := ids(s.b, "exit-de-2", "master-xa-1")
	if u1 == u2 || s1 == s2 || u1 == u3 {
		t.Error("portal ids collide across pairs")
	}
	if again, _ := ids(s.b, "exit-de-1", "master-xa-1"); again != u1 {
		t.Error("portal ids are not stable")
	}
	fu, _, err := s.b.tunnelIDs(ctx, "exit-de-1", "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if u1 == fu {
		t.Error("portal id equals the forward REALITY id")
	}
	other := newReverseSetup(t)
	if u, _ := ids(other.b, "exit-de-1", "master-xa-1"); u == u1 {
		t.Error("a second controller computed the same id: it is derivable")
	}
}
