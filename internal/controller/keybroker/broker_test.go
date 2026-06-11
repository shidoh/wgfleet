package keybroker

import (
	"context"
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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)

	spec, err := b.RenderNodeSpec(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Role != domain.RoleExit || spec.Egress != domain.EgressWARP {
		t.Fatalf("role/egress = %v/%v", spec.Role, spec.Egress)
	}
	if spec.WGServer.ListenPort != config.DefaultExitListenPort {
		t.Errorf("listen port = %d, want default %d", spec.WGServer.ListenPort, config.DefaultExitListenPort)
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
	if mp.Name != "master-xa-1" || mp.PublicKey != "MASTERPUB==" {
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
	if !spec.Firewall.ASBlacklist || spec.Firewall.WGPort != config.DefaultExitListenPort {
		t.Errorf("firewall = %+v", spec.Firewall)
	}
	if !spec.Exporters.WARP {
		t.Error("WARP exporter should be enabled for warp egress")
	}
	if err := spec.Validate(); err != nil {
		t.Errorf("rendered exit spec should be valid: %v", err)
	}
}

func TestRenderMasterSpec(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)

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
	if et.Name != "exit-de-1" || et.ServerPublicKey != "EXITPUB==" {
		t.Errorf("exit tunnel = %+v", et)
	}
	if et.Endpoint != "198.51.100.7:51820" {
		t.Errorf("exit tunnel endpoint = %q", et.Endpoint)
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

func TestRenderSkipsUnregisteredPeer(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t)
	// Master registered, exit NOT (no pubkey yet).
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
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

	if err := b.RegisterPublicKey(ctx, "exit-de-1", "FRESHPUB=="); err != nil {
		t.Fatalf("register: %v", err)
	}
	node, _ := st.GetNode(ctx, "exit-de-1")
	if node.PublicKey != "FRESHPUB==" {
		t.Errorf("public key = %q", node.PublicKey)
	}
	if err := b.RegisterPublicKey(ctx, "exit-de-1", ""); err == nil {
		t.Error("empty public key should be rejected")
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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)
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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)

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
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)
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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)
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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)

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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1", "MASTERPUB==", domain.RoleMaster)
	seedNode(t, st, "exit-de-1", "10.20.0.5", "198.51.100.7", "EXITPUB==", domain.RoleExit)

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
