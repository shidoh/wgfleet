package keybroker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

// The operator changed an exit's public_ip in the manifest (the node moved to a
// new address) and restarted the controller. The store still carries the address
// seeded at first provisioning — nothing ever refreshes it, and the agent does not
// advertise one. The rendered master↔exit endpoint must follow the manifest.
func TestExitPublicIPChangeInManifestWins(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Exits[0].PublicIP = "198.51.100.99" // new address, declared by the operator
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	// Stale store row: the address the exit had when it was first provisioned.
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master == nil || len(spec.Master.ExitTunnels) != 1 {
		t.Fatalf("expected 1 exit tunnel, got %+v", spec.Master)
	}
	want := fmt.Sprintf("198.51.100.99:%d", config.ExitConfig{Name: "exit-de-1"}.WGListenPort())
	if got := spec.Master.ExitTunnels[0].Endpoint; got != want {
		t.Errorf("exit endpoint = %q, want %q (manifest public_ip)", got, want)
	}
	if !contains(spec.Master.DirectCIDRs, "198.51.100.99/32") {
		t.Errorf("new public IP missing from DIRECT cidrs: %v", spec.Master.DirectCIDRs)
	}
	if contains(spec.Master.DirectCIDRs, "198.51.100.7/32") {
		t.Errorf("stale public IP still in DIRECT cidrs: %v", spec.Master.DirectCIDRs)
	}
}

// The same change made the way most manifests are written: public_ip is left
// unset (it defaults to ssh.host, as documented) and the operator repoints ssh.host
// at the node's new address. The master must follow that too — the stale store row
// must not pin the endpoint.
func TestExitSSHHostChangeInManifestWins(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Exits[0].SSH = config.SSHConfig{Host: "198.51.100.99", User: "root"}
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := fmt.Sprintf("198.51.100.99:%d", config.ExitConfig{Name: "exit-de-1"}.WGListenPort())
	if got := spec.Master.ExitTunnels[0].Endpoint; got != want {
		t.Errorf("exit endpoint = %q, want %q (manifest ssh.host)", got, want)
	}
}

// An exit the manifest describes by name only — no public_ip, no ssh (hand-
// onboarded, or re-added after its store record was deleted) — still renders an
// endpoint from whatever the store carries. An empty one would fail the whole
// master render.
func TestExitPublicIPFallsBackToStore(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t) // testFleet(): exit with neither public_ip nor ssh
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := fmt.Sprintf("198.51.100.7:%d", config.ExitConfig{Name: "exit-de-1"}.WGListenPort())
	if got := spec.Master.ExitTunnels[0].Endpoint; got != want {
		t.Errorf("exit endpoint = %q, want the store's %q", got, want)
	}
}

// Same for the master's own address: the exit's direct route back to the master
// (an earlier finding — the return path must not go into WARP) and the master's own DNAT
// guard must follow the manifest, not the store snapshot.
func TestMasterPublicIPChangeInManifestWins(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Masters[0].PublicIP = "203.0.113.42" // new address
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	ms, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render master: %v", err)
	}
	if !contains(ms.Master.DirectCIDRs, "203.0.113.42/32") {
		t.Errorf("master DIRECT cidrs = %v, want the manifest public_ip", ms.Master.DirectCIDRs)
	}
	if ms.Master.Compose.PublicIP != "203.0.113.42" {
		t.Errorf("compose public IP = %q, want 203.0.113.42 (manifest)", ms.Master.Compose.PublicIP)
	}

	es, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	if es.Routing.MasterIP != "203.0.113.42" {
		t.Errorf("exit routing MasterIP = %q, want 203.0.113.42 (manifest)", es.Routing.MasterIP)
	}
}

// A master that was never SSH-provisioned has no public IP in the store; the
// manifest is then the only source. And a manifest that declares none must still
// fall back to whatever the store discovered.
func TestMasterPublicIPFallsBackToStoreWhenManifestSilent(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t) // testFleet(): master without public_ip
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	ms, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render master: %v", err)
	}
	if ms.Master.Compose.PublicIP != "203.0.113.1" {
		t.Errorf("compose public IP = %q, want the store's 203.0.113.1", ms.Master.Compose.PublicIP)
	}
	es, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	if es.Routing.MasterIP != "203.0.113.1" {
		t.Errorf("exit routing MasterIP = %q, want the store's 203.0.113.1", es.Routing.MasterIP)
	}
}

// The REALITY/XHTTP tunnel dials the same address the AWG one does, so a
// dual-transport exit that moves must move on BOTH transports. Nothing but this
// test distinguishes which source that endpoint came from.
func TestExitPublicIPChangeMovesRealityTunnelToo(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Exits[0].Transports = config.TransportsConfig{
		AWG:     config.AWGTransportConfig{Enabled: true},
		Reality: config.RealityTransportConfig{Enabled: true},
	}
	fleet.Exits[0].SSH = config.SSHConfig{Host: "198.51.100.7"} // stale, matches the store
	fleet.Exits[0].PublicIP = "198.51.100.99"                   // the operator's new address
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	_, realityPub, err := xray.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeRealityKey(ctx, "exit-de-1", realityPub); err != nil {
		t.Fatal(err)
	}

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var seen int
	for _, tn := range spec.Master.ExitTunnels {
		seen++
		if !strings.HasPrefix(tn.Endpoint, "198.51.100.99:") {
			t.Errorf("%s tunnel endpoint = %q, want the manifest address 198.51.100.99",
				tn.Transport.OrDefault(), tn.Endpoint)
		}
	}
	if seen != 2 {
		t.Fatalf("expected both transports rendered, got %d tunnels", seen)
	}
}

// A DNS name in an exit's public_ip cannot be dialled by mihomo's WireGuard
// outbound (the endpoint is rendered as ip:port), so it must not cost the exit its
// place in the load balancer: resolution falls through to the next source.
func TestExitNonIPPublicIPFallsThrough(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Exits[0].PublicIP = "exit-de-1.example.net"
	fleet.Exits[0].SSH = config.SSHConfig{Host: "198.51.100.42"}
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(spec.Master.ExitTunnels) != 1 {
		t.Fatalf("exit dropped from the master over a DNS name in public_ip: %+v", spec.Master.ExitTunnels)
	}
	want := fmt.Sprintf("198.51.100.42:%d", config.ExitConfig{Name: "exit-de-1"}.WGListenPort())
	if got := spec.Master.ExitTunnels[0].Endpoint; got != want {
		t.Errorf("endpoint = %q, want the next usable source %q", got, want)
	}
}

// docs/master-migration.md tells operators to put a DNS NAME in the master's
// public_ip so a future move is a DNS record change. That name is right for client
// profiles and unusable for the kernel: `ip rule add to <name>` does not resolve,
// and that step is not best-effort — a name reaching it fails every WARP exit's
// routing reconcile on every pass, so an earlier finding's "replies to the master stay
// direct" rule never gets installed. The two uses must resolve separately.
func TestMasterDNSNameServesClientsButNotTheKernel(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Masters[0].PublicIP = "vpn.example.net"
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	ms, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render master: %v", err)
	}
	if ms.Master.Compose.PublicIP != "vpn.example.net" {
		t.Errorf("client-facing host = %q, want the DNS name", ms.Master.Compose.PublicIP)
	}
	if contains(ms.Master.DirectCIDRs, "vpn.example.net/32") {
		t.Error("a DNS name must never reach DIRECT cidrs")
	}
	if !contains(ms.Master.DirectCIDRs, "203.0.113.1/32") {
		t.Errorf("kernel guard lost the master's own address: %v", ms.Master.DirectCIDRs)
	}

	es, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	if es.Routing.MasterIP != "203.0.113.1" {
		t.Errorf("exit routing MasterIP = %q, want an IP literal the kernel can use", es.Routing.MasterIP)
	}
}

// With no IP literal anywhere, the kernel-level guards are omitted rather than
// rendered with a name that `ip rule` would reject on every pass.
func TestMasterWithoutIPLiteralOmitsKernelGuards(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.Masters[0].PublicIP = "vpn.example.net"
	b, st := newBrokerWithFleet(t, fleet)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	es, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	if es.Routing.MasterIP != "" {
		t.Errorf("routing MasterIP = %q, want empty (no usable literal)", es.Routing.MasterIP)
	}
	ms, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render master: %v", err)
	}
	for _, c := range ms.Master.DirectCIDRs {
		if strings.Contains(c, "example.net") {
			t.Errorf("DNS name leaked into DIRECT cidrs: %v", ms.Master.DirectCIDRs)
		}
	}
	// The client-facing name still works — only the kernel guards drop out.
	if ms.Master.Compose.PublicIP != "vpn.example.net" {
		t.Errorf("client-facing host = %q, want the DNS name", ms.Master.Compose.PublicIP)
	}
}

// An exit dialled over the management overlay is worth saying out loud once — and
// exactly once. Specs render per node every ~30s, so a warning about a standing
// manifest choice that logged on every pass would print thousands of identical
// lines a day and bury the fleet's real events, which is the churn Register was
// fixed for. It must also say it again if the address changes.
func TestOverlayEndpointWarningIsNotRepeatedEveryRender(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	// public_ip unset and ssh pointed at the exit's own mgmt address — the
	// documented workaround for a black-holed direct path.
	fleet.Exits[0].MgmtAddr = "10.20.0.5"
	fleet.Exits[0].SSH = config.SSHConfig{Host: "10.20.0.5"}

	var logs bytes.Buffer
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	b := New(st, fleet, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	for i := 0; i < 3; i++ {
		if _, err := b.RenderNodeSpec(ctx, "master-xa-1"); err != nil {
			t.Fatalf("render %d: %v", i, err)
		}
	}
	if n := strings.Count(logs.String(), "management-overlay address"); n != 1 {
		t.Errorf("overlay warning logged %d times across 3 renders, want exactly 1:\n%s", n, logs.String())
	}
}
