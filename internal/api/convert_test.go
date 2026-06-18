package api

import (
	"reflect"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestNodeSpecRoundTrip(t *testing.T) {
	spec := domain.NodeSpec{
		Role:   domain.RoleExit,
		Egress: domain.EgressWARP,
		WGServer: domain.WGServerSpec{
			ListenPort:  51820,
			AddressPool: "10.81.0.0/24",
			Address:     "10.81.0.1",
			MTU:         1380,
			AWG: &domain.AWGParams{
				Shared: domain.AWGShared{
					H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
					H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
					H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
					H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
					S1: 102, S2: 67, S3: 143, S4: 38,
				},
				Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900, I1: "<b 0xdeadbeef>", I2: "<r 8>"},
			},
		},
		Peers: []domain.PeerSpec{
			{
				Name:       "master-xa-1",
				PublicKey:  "PUBKEY==",
				Endpoint:   "master.mgmt:443",
				AllowedIPs: []string{"10.81.0.2/32"},
				Keepalive:  25,
				MTU:        1320,
			},
		},
		DNS: domain.DNSFilterSpec{
			Enabled:    true,
			MgmtAddr:   "10.20.0.5",
			Ports:      domain.DNSPorts{DNS: 53, TLS: 853},
			Upstreams:  []string{"1.1.1.1"},
			Allowlist:  []string{"*.example.com"},
			Prometheus: true,
			Image:      "spx01/blocky",
			BootstrapDNS: []domain.BootstrapUpstream{
				{Upstream: "tcp-tls:dns.quad9.net", IPs: []string{"9.9.9.9"}},
			},
			Custom: domain.CustomConfig{
				Overrides: map[string]any{"caching": map[string]any{"prefetching": true}},
			},
		},
		Firewall: domain.FirewallSpec{ASBlacklist: true, Whitelist: []string{"10.20.0.0/16"}, WGPort: 51820},
		Routing: domain.RoutingSpec{
			EgressInterface: "wgcf",
			DirectCIDRs:     []string{"10.0.0.0/8"},
			MasterIP:        "203.0.113.1",
			FwMark:          0x1,
		},
		Exporters: domain.ExportersSpec{Node: true, WG: true, WARP: true},
	}

	got := SpecFromProto(SpecToProto(spec))

	if !reflect.DeepEqual(spec, got) {
		t.Fatalf("round-trip mismatch:\n got = %+v\nwant = %+v", got, spec)
	}
}

func TestNodeSpecRoundTripMinimal(t *testing.T) {
	// No AWG, no peers: pointers must stay nil through the round-trip.
	spec := domain.NodeSpec{
		Role:     domain.RoleMaster,
		WGServer: domain.WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"},
	}
	got := SpecFromProto(SpecToProto(spec))
	if got.WGServer.AWG != nil {
		t.Errorf("expected nil structural AWG, got %+v", got.WGServer.AWG)
	}
	if len(got.Peers) != 0 {
		t.Errorf("expected no peers, got %d", len(got.Peers))
	}
	if !reflect.DeepEqual(spec, got) {
		t.Fatalf("minimal round-trip mismatch:\n got = %+v\nwant = %+v", got, spec)
	}
}

func TestStatusRoundTrip(t *testing.T) {
	hs := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	st := domain.NodeStatus{
		NodeID:         "exit-de-1",
		State:          domain.StateReady,
		EgressIP:       "104.16.0.1",
		ReconcileError: "",
		LastHandshake:  hs,
		Checks: []domain.HealthCheck{
			{Name: "warp-egress", OK: true, Detail: "cloudflare", Latency: 42 * time.Millisecond},
		},
	}

	got := StatusFromProto(st.NodeID, StatusToProto(st))

	if got.NodeID != st.NodeID || got.State != st.State || got.EgressIP != st.EgressIP {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if !got.LastHandshake.Equal(hs) {
		t.Errorf("handshake = %v want %v", got.LastHandshake, hs)
	}
	if len(got.Checks) != 1 || got.Checks[0].Latency != 42*time.Millisecond {
		t.Errorf("checks mismatch: %+v", got.Checks)
	}
}

func TestMasterSpecRoundTrip(t *testing.T) {
	awg := &domain.AWGParams{
		Shared: domain.AWGShared{
			H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
			H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
			H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
			H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
			S1: 102, S2: 67, S3: 143, S4: 38,
		},
		Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900, I1: "<r 2><b 0xdead>"},
	}
	spec := domain.NodeSpec{
		Role:     domain.RoleMaster,
		WGServer: domain.WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"},
		Master: &domain.MasterSpec{
			BindAddress:        "10.80.0.1",
			RedirPort:          7895,
			ExternalController: "10.20.25.254:9090",
			Balance:            "consistent-hashing",
			DirectCIDRs:        []string{"10.0.0.0/8"},
			DirectGeo:          []string{"RU"},
			SnifferSkip:        []string{"+.themoviedb.org"},
			DashboardDisabled:  true,
			DashboardURL:       "https://mirror.example.ru/zashboard.zip",
			ClientAdminPorts:   []int{9000, 9090, 51821},
			ExitTunnels: []domain.ExitTunnel{
				{
					Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
					ServerPublicKey: "EXITPUB==", PresharedKey: "PSK==",
					TunnelIP: "10.81.0.2", MTU: 1360, AWG: awg,
				},
			},
			Custom: domain.CustomConfig{
				Overrides: map[string]any{"log-level": "debug", "dns": map[string]any{"listen": "0.0.0.0:53"}},
				Files:     []domain.ManagedFile{{Path: "/etc/mihomo/extra.yaml", Content: "x: 1", Secret: false}},
			},
		},
	}

	got := SpecFromProto(SpecToProto(spec))
	if got.Master == nil {
		t.Fatal("master spec lost in round-trip")
	}
	m := got.Master
	if m.BindAddress != "10.80.0.1" || m.RedirPort != 7895 || m.Balance != "consistent-hashing" {
		t.Errorf("master scalars mismatch: %+v", m)
	}
	// Dashboard controls must cross the wire (they were lost once — proto field gap).
	if !m.DashboardDisabled || m.DashboardURL != "https://mirror.example.ru/zashboard.zip" {
		t.Errorf("dashboard fields lost in round-trip: disabled=%v url=%q", m.DashboardDisabled, m.DashboardURL)
	}
	// Client admin ports must cross the wire too — they were lost once (proto field
	// gap): the controller served them but the agent rendered no firewall accepts.
	if len(m.ClientAdminPorts) != 3 || m.ClientAdminPorts[0] != 9000 || m.ClientAdminPorts[2] != 51821 {
		t.Errorf("client admin ports lost in round-trip: %v", m.ClientAdminPorts)
	}
	if len(m.ExitTunnels) != 1 {
		t.Fatalf("exit tunnels = %d", len(m.ExitTunnels))
	}
	tn := m.ExitTunnels[0]
	if tn.Name != "exit-de-1" || tn.TunnelIP != "10.81.0.2" || tn.MTU != 1360 || tn.PresharedKey != "PSK==" {
		t.Errorf("exit tunnel mismatch: %+v", tn)
	}
	if tn.AWG == nil || tn.AWG.Shared.H1.Min != 15384729 || tn.AWG.Local.Jc != 5 {
		t.Errorf("exit tunnel AWG mismatch: %+v", tn.AWG)
	}
	// Custom overrides survive as JSON round-trip.
	if m.Custom.Overrides["log-level"] != "debug" {
		t.Errorf("override scalar lost: %v", m.Custom.Overrides["log-level"])
	}
	dns, _ := m.Custom.Overrides["dns"].(map[string]any)
	if dns == nil || dns["listen"] != "0.0.0.0:53" {
		t.Errorf("nested override lost: %v", m.Custom.Overrides["dns"])
	}
	if len(m.Custom.Files) != 1 || m.Custom.Files[0].Path != "/etc/mihomo/extra.yaml" {
		t.Errorf("custom files lost: %+v", m.Custom.Files)
	}
}
