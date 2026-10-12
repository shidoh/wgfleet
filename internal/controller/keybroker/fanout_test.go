package keybroker

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// declaredOverlayFleet is twoMasterFleet with the management overlay declared as
// one subnet. Without mgmt_subnet the overlay is the /32 of every node's
// mgmt_addr, so a master entering or leaving the manifest also moves a /32 in
// every exit's direct list and firewall whitelist — as any node joining always
// has. The tests that compare a one-master render with a two-master one are
// about the peers and the route back, and pin the overlay to keep that apart.
func declaredOverlayFleet() config.FleetSection {
	f := twoMasterFleet()
	f.MgmtSubnet = "10.20.25.0/24"
	return f
}

func TestEveryMasterGetsItsOwnPeersAndAddresses(t *testing.T) {
	type peer struct{ key, addr string }
	cases := []struct {
		phase domain.PerTunnelKeyPhase
		// which identity each master holds on which address, and the one it dials from
		legacy, perTunnel bool
		dialPerTunnel     bool
	}{
		{domain.PerTunnelKeyOff, true, false, false},
		{domain.PerTunnelKeyDual, true, true, false},
		{domain.PerTunnelKeySwitch, true, true, true},
		{domain.PerTunnelKeyOn, false, true, true},
	}
	addrs := map[string][2]string{ // master → {legacy, per-tunnel}
		"master-xa-1": {"10.81.0.2", "10.81.0.3"},
		"master-xa-2": {"10.81.0.4", "10.81.0.5"},
	}
	for _, c := range cases {
		t.Run(string(c.phase), func(t *testing.T) {
			fleet := twoMasterFleet()
			fleet.Exits[0].PerTunnelKey = string(c.phase)
			s := seedTwoMasters(t, fleet)
			exitSpec := mustRender(t, s.b, "exit-de-1")

			owner := map[string]string{} // allowed-ip → public key
			for _, p := range exitSpec.Peers {
				for _, ip := range p.AllowedIPs {
					if prev, dup := owner[ip]; dup {
						t.Fatalf("%s is claimed by two peers (%s…, %s…): the second steals it and the first black-holes", ip, prev[:8], p.PublicKey[:8])
					}
					owner[ip] = p.PublicKey
				}
			}
			want := map[string]string{}
			for master, a := range addrs {
				if c.legacy {
					want[a[0]+"/32"] = s.sharedPubs[master]
				}
				if c.perTunnel {
					want[a[1]+"/32"] = s.tunnelPubs[master]
				}
			}
			if !reflect.DeepEqual(owner, want) {
				t.Errorf("exit allowed-ips → key = %v\nwant %v", owner, want)
			}
			for master, a := range addrs {
				tun, _ := tunnelByName(mustRender(t, s.b, master).Master.ExitTunnels, "exit-de-1")
				dial := a[0]
				if c.dialPerTunnel {
					dial = a[1]
				}
				if tun.TunnelIP != dial {
					t.Errorf("%s dials from %s, want %s", master, tun.TunnelIP, dial)
				}
			}
		})
	}
}

// Replies to EVERY master must stay off the egress: the base master
// through MasterIP as always, the others through a host route — appended, so the
// rules that were there keep their priorities.
func TestExitKeepsTheReturnPathToEveryMasterDirect(t *testing.T) {
	two := seedTwoMasters(t, declaredOverlayFleet())
	got := mustRender(t, two.b, "exit-de-1").Routing

	oneFleet := declaredOverlayFleet()
	oneFleet.Masters = oneFleet.Masters[:1]
	one := mustRender(t, seedTwoMasters(t, oneFleet).b, "exit-de-1").Routing

	if got.MasterIP != "203.0.113.1" {
		t.Errorf("MasterIP = %q, want the base master's", got.MasterIP)
	}
	want := append(append([]string(nil), one.DirectCIDRs...), "203.0.113.2/32")
	if !slices.Equal(got.DirectCIDRs, want) {
		t.Errorf("DirectCIDRs = %v\nwant the one-master list with one host appended: %v", got.DirectCIDRs, want)
	}
	// Another master's direct_cidrs must not change where the base master's
	// clients leave from: 172.16.0.0/12 is master-xa-2's.
	if slices.Contains(got.DirectCIDRs, "172.16.0.0/12") {
		t.Error("a non-base master's direct_cidrs reached the exit")
	}
}

// Review Focus 1. A master written into the manifest ahead of its deployment
// leaves the interface and the peers exactly as they were and appends one route.
func TestUndeployedMasterOnlyAppendsOneRoute(t *testing.T) {
	oneFleet := declaredOverlayFleet()
	oneFleet.Masters = oneFleet.Masters[:1]
	s := seedTwoMasters(t, oneFleet)
	before := mustRender(t, s.b, "exit-de-1")

	b := New(s.st, declaredOverlayFleet(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	after := mustRender(t, b, "exit-de-1")

	if !reflect.DeepEqual(after.WGServer, before.WGServer) {
		t.Error("the exit interface changed for a master that is only a manifest entry")
	}
	if !reflect.DeepEqual(after.Peers, before.Peers) {
		t.Errorf("peers changed: %d → %d", len(before.Peers), len(after.Peers))
	}
	want := append(append([]string(nil), before.Routing.DirectCIDRs...), "203.0.113.2/32")
	if !slices.Equal(after.Routing.DirectCIDRs, want) {
		t.Errorf("DirectCIDRs = %v, want %v", after.Routing.DirectCIDRs, want)
	}
	after.Routing.DirectCIDRs = before.Routing.DirectCIDRs
	if !reflect.DeepEqual(after.Routing, before.Routing) {
		t.Error("routing changed in more than the one appended host")
	}
}

// Review Focus 2. The base master is dead: the operator deletes it from the
// manifest and the store. Nothing may move for the master that is left — this is
// the event several masters exist for.
func TestRemovingADeadMasterChangesNothingForTheSurvivor(t *testing.T) {
	fleet := twoMasterFleet()
	s := seedTwoMasters(t, fleet)
	exitBefore := mustRender(t, s.b, "exit-de-1")
	masterBefore := mustRender(t, s.b, "master-xa-2")

	survivor := twoMasterFleet()
	survivor.Masters = survivor.Masters[1:] // master-xa-2 keeps slot 1; the anchor label stays
	if err := s.st.DeleteNode(context.Background(), "master-xa-1"); err != nil {
		t.Fatal(err)
	}
	b := New(s.st, survivor, slog.New(slog.NewTextHandler(io.Discard, nil)))
	exitAfter := mustRender(t, b, "exit-de-1")
	masterAfter := mustRender(t, b, "master-xa-2")

	if !reflect.DeepEqual(exitAfter.WGServer, exitBefore.WGServer) {
		t.Error("the exit interface was re-keyed when the base master left")
	}
	if !reflect.DeepEqual(exitAfter.Reality, exitBefore.Reality) {
		t.Error("the exit's REALITY inbound was re-keyed when the base master left")
	}
	for _, key := range []string{s.sharedPubs["master-xa-2"], s.tunnelPubs["master-xa-2"]} {
		pb, okB := peerByKey(exitBefore.Peers, key)
		pa, okA := peerByKey(exitAfter.Peers, key)
		if okA != okB || !reflect.DeepEqual(pa, pb) {
			t.Errorf("the survivor's peer %s… changed: %+v → %+v", key[:8], pb, pa)
		}
	}
	if _, ok := peerByKey(exitAfter.Peers, s.sharedPubs["master-xa-1"]); ok {
		t.Error("the dead master's peer is still on the exit")
	}
	tb, _ := tunnelByName(masterBefore.Master.ExitTunnels, "exit-de-1")
	ta, _ := tunnelByName(masterAfter.Master.ExitTunnels, "exit-de-1")
	if !reflect.DeepEqual(ta, tb) {
		t.Errorf("the survivor's tunnel changed:\n%+v\n→\n%+v", tb, ta)
	}
}

// Review Focus 5. An exit whose agent predates multi-master would restart awg0
// for a new peer and flush conntrack for a new route. It is rendered the base
// master and nothing else, and the other master does not dial it over AWG.
func TestOldExitGetsOnlyTheBaseMaster(t *testing.T) {
	fleet := declaredOverlayFleet()
	s := seedTwoMasters(t, fleet)
	oneFleet := declaredOverlayFleet()
	oneFleet.Masters = oneFleet.Masters[:1]

	setWireVersion(t, s.st, "exit-de-1", api.WireMasterPeers-1)
	// The one-master fleet, rendered against the same store and the same older exit.
	want := mustRender(t, New(s.st, oneFleet, slog.New(slog.NewTextHandler(io.Discard, nil))), "exit-de-1")
	got := mustRender(t, s.b, "exit-de-1")
	if !reflect.DeepEqual(got, want) {
		t.Error("an exit below the multi-master wire version was rendered something a one-master fleet would not render it")
	}
	spec := mustRender(t, s.b, "master-xa-2")
	if _, ok := tunnelByName(spec.Master.ExitTunnels, "exit-de-1"); ok {
		t.Error("a non-base master was given an AWG tunnel to an exit that holds no peer for it")
	}
	if _, ok := tunnelByName(spec.Master.ExitTunnels, "exit-de-1-reality"); !ok {
		t.Error("the REALITY tunnel needs no peer on the exit and must stay")
	}
}

// A master the fleet has never heard from contributes no peer, and does not hold
// back the masters that are there.
func TestMasterWithoutAKeyIsSkippedNotFatal(t *testing.T) {
	oneFleet := twoMasterFleet()
	oneFleet.Masters = oneFleet.Masters[:1]
	s := seedTwoMasters(t, oneFleet)
	spec := mustRender(t, New(s.st, twoMasterFleet(), slog.New(slog.NewTextHandler(io.Discard, nil))), "exit-de-1")
	if _, ok := peerByKey(spec.Peers, s.sharedPubs["master-xa-1"]); !ok {
		t.Error("the base master's peer disappeared along with the missing master's")
	}
	for _, p := range spec.Peers {
		if strings.HasPrefix(p.Name, "master-xa-2") {
			t.Errorf("peer %q rendered for a master with no published key", p.Name)
		}
	}
}
