package keybroker

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// uplinkFleet is four masters around master-xa-1, one for each way a peer can or
// cannot be measured.
func uplinkFleet() config.FleetSection {
	f := testFleet()
	self := f.Masters[0]
	self.PublicIP = "203.0.113.1"

	vless := self
	vless.Name, vless.Slot, vless.MgmtAddr, vless.PublicIP = "master-vless", 1, "10.20.25.253", "203.0.113.2"
	vless.ClientVLESS = config.ClientVLESSConfig{Enabled: true, ListenPort: 8443}

	storeOnly := self
	storeOnly.Name, storeOnly.Slot, storeOnly.MgmtAddr, storeOnly.PublicIP = "master-store", 2, "10.20.25.252", ""
	storeOnly.PublicTCPPorts = []int{5201, 80}

	closed := self
	closed.Name, closed.Slot, closed.MgmtAddr, closed.PublicIP = "master-closed", 3, "10.20.25.251", "203.0.113.4"

	named := self
	named.Name, named.Slot, named.MgmtAddr, named.PublicIP = "master-named", 4, "10.20.25.250", "m5.example"
	named.PublicTCPPorts = []int{443}

	f.Masters = []config.MasterConfig{self, vless, storeOnly, closed, named}
	return f
}

func TestUplinkProbeTargetsArePeersWithAnOpenPort(t *testing.T) {
	b, st := newBrokerWithFleet(t, uplinkFleet())
	seedNode(t, st, "master-store", "10.20.25.252", "198.51.100.3", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)

	got := b.uplinkProbeTargets(context.Background(), b.fleet.Masters[0])

	want := []domain.UplinkProbeTarget{
		{Name: "master-vless", Addr: netip.MustParseAddrPort("203.0.113.2:8443")},
		{Name: "master-store", Addr: netip.MustParseAddrPort("198.51.100.3:5201")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %+v\nwant %+v", got, want)
	}
}

// The client VLESS port wins over public_tcp_ports: it is the port the master is
// built to keep open, while public_tcp_ports holds whatever an operator once
// needed (an iperf3 that is started by hand answers nothing most of the time).
func TestUplinkProbeTargetPrefersTheClientVLESSPort(t *testing.T) {
	f := uplinkFleet()
	f.Masters[1].PublicTCPPorts = []int{5201}
	b, _ := newBrokerWithFleet(t, f)

	got := b.uplinkProbeTargets(context.Background(), f.Masters[0])

	if len(got) == 0 || got[0].Addr.Port() != 8443 {
		t.Fatalf("targets = %+v, want master-vless on its VLESS port 8443", got)
	}
}

func TestUplinkProbeTargetsEmptyForASingleMaster(t *testing.T) {
	b, _ := newBrokerWithFleet(t, testFleet())
	if got := b.uplinkProbeTargets(context.Background(), b.fleet.Masters[0]); len(got) != 0 {
		t.Fatalf("targets = %+v, want none", got)
	}
}

// The rendered spec carries the targets: the helper being right is worth nothing
// if renderMasterSpec never calls it.
func TestRenderMasterSpecCarriesUplinkProbeTargets(t *testing.T) {
	b, st := newBrokerWithFleet(t, uplinkFleet())
	seedTestMaster(t, st, b.fleet.Masters[0].Name)
	spec, err := b.renderMasterSpec(context.Background(), b.fleet.Masters[0])
	if err != nil {
		t.Fatal(err)
	}
	if spec.Master == nil || len(spec.Master.UplinkProbeTargets) == 0 {
		t.Fatalf("rendered master spec has no uplink probe targets: %+v", spec.Master)
	}
	if spec.Master.UplinkProbeTargets[0].Name != "master-vless" {
		t.Errorf("first target = %+v, want master-vless", spec.Master.UplinkProbeTargets[0])
	}
}

// A probe opens and closes a connection every 30 s. Aimed at sshd, that is a
// "Connection closed [preauth]" line per probe, which fail2ban turns into one
// master banning another — after which every probe reads as a dead uplink.
func TestUplinkProbeNeverAimsAtSSH(t *testing.T) {
	f := uplinkFleet()
	f.Masters[2].PublicTCPPorts = []int{22, 2222, 5201}
	f.Masters[2].SSH.Port = 2222
	b, st := newBrokerWithFleet(t, f)
	seedNode(t, st, "master-store", "10.20.25.252", "198.51.100.3", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)

	found := false
	for _, tg := range b.uplinkProbeTargets(context.Background(), f.Masters[0]) {
		if tg.Name != "master-store" {
			continue
		}
		found = true
		if tg.Addr.Port() != 5201 {
			t.Fatalf("master-store probed on port %d, want 5201 (22 and its ssh port are skipped)", tg.Addr.Port())
		}
	}
	if !found {
		t.Fatal("master-store is not a target at all; want it on 5201")
	}
}
