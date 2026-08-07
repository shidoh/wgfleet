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
		Exporters:                domain.ExportersSpec{Node: true, WG: true, WARP: true},
		WARPMTU:                  1380,
		EgressChain:              []domain.EgressMethod{domain.EgressWARP, domain.EgressDirect},
		EgressThroughputMinBps:   256000,
		EgressThroughputProbeURL: "https://speed.cloudflare.com/__down?bytes=262144",
		EnabledTransports:        []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		ActiveTransport:          domain.TransportAWG,
		Reality: &domain.RealityServerSpec{
			ListenPort: 8443, UUID: "uuid-1", ShortID: "0badc0de", ServerName: "www.microsoft.com",
			Dest: "www.microsoft.com:443", XHTTPPath: "/down", XHTTPMode: "packet-up",
			Image: "ghcr.io/xtls/xray-core:25.6.22",
		},
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
			BindAddress:         "10.80.0.1",
			RedirPort:           7895,
			ExternalController:  "10.20.25.254:9090",
			Balance:             "consistent-hashing",
			HealthCheckInterval: 30,
			DirectCIDRs:         []string{"10.0.0.0/8"},
			DirectGeo:           []string{"RU"},
			SnifferSkip:         []string{"+.themoviedb.org"},
			DashboardDisabled:   true,
			DashboardURL:        "https://mirror.example.ru/zashboard.zip",
			ClientAdminPorts:    []int{9000, 9090, 51821},
			ExitTunnels: []domain.ExitTunnel{
				{
					Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
					ServerPublicKey: "EXITPUB==", PresharedKey: "PSK==",
					TunnelIP: "10.81.0.2", MTU: 1360, AWG: awg,
				},
				{
					Name: "exit-de-1-reality", Endpoint: "198.51.100.7:443",
					Transport: domain.TransportRealityXHTTP, Drained: true,
					Reality: &domain.RealityTunnel{
						UUID: "uuid-1", PublicKey: "RPUB==", ShortID: "0badc0de",
						ServerName: "www.microsoft.com", Fingerprint: "chrome",
						XHTTPPath: "/down", XHTTPMode: "packet-up",
					},
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
	if m.HealthCheckInterval != 30 {
		t.Errorf("health_check_interval lost in round-trip: %d", m.HealthCheckInterval)
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
	if len(m.ExitTunnels) != 2 {
		t.Fatalf("exit tunnels = %d", len(m.ExitTunnels))
	}
	tn := m.ExitTunnels[0]
	if tn.Name != "exit-de-1" || tn.TunnelIP != "10.81.0.2" || tn.MTU != 1360 || tn.PresharedKey != "PSK==" {
		t.Errorf("exit tunnel mismatch: %+v", tn)
	}
	if tn.AWG == nil || tn.AWG.Shared.H1.Min != 15384729 || tn.AWG.Local.Jc != 5 {
		t.Errorf("exit tunnel AWG mismatch: %+v", tn.AWG)
	}
	// The REALITY/XHTTP tunnel must survive the round-trip with its transport
	// discriminator and reality params intact (ADR-0025).
	rt := m.ExitTunnels[1]
	if rt.Transport != domain.TransportRealityXHTTP || !rt.Drained || rt.Reality == nil {
		t.Fatalf("reality tunnel mismatch: %+v", rt)
	}
	if rt.Reality.PublicKey != "RPUB==" || rt.Reality.ShortID != "0badc0de" ||
		rt.Reality.XHTTPMode != "packet-up" || rt.Reality.Fingerprint != "chrome" {
		t.Errorf("reality tunnel params lost in round-trip: %+v", rt.Reality)
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

func TestMasterSpecRoundTripCarriesTiering(t *testing.T) {
	in := &domain.MasterSpec{
		BindAddress:    "10.73.0.1",
		Balance:        "consistent-hashing",
		MaxFailedTimes: 10,
		ExitTunnels: []domain.ExitTunnel{
			{Name: "vn1", Endpoint: "1.2.3.4:51820", Reserve: false},
			{Name: "anz3", Endpoint: "5.6.7.8:51820", Reserve: true},
		},
	}

	out := masterFromProto(masterToProto(in))

	if out.MaxFailedTimes != 10 {
		t.Errorf("MaxFailedTimes = %d, want 10", out.MaxFailedTimes)
	}
	if len(out.ExitTunnels) != 2 {
		t.Fatalf("got %d tunnels, want 2", len(out.ExitTunnels))
	}
	if out.ExitTunnels[0].Reserve {
		t.Error("vn1 must round-trip as primary")
	}
	if !out.ExitTunnels[1].Reserve {
		t.Error("anz3 must round-trip as reserve")
	}
}

func TestStatusExitHealthRoundTrip(t *testing.T) {
	in := domain.NodeStatus{
		NodeID: "master-xa-1",
		State:  domain.StateReady,
		ExitHealth: []domain.ExitTunnelHealth{
			{Name: "exit-de-1", Alive: true, Delay: 42 * time.Millisecond, LastTest: time.Unix(1000, 0).UTC(), Selected: true},
			{Name: "exit-nl-1", Alive: false},
		},
	}
	out := StatusFromProto("master-xa-1", StatusToProto(in))
	if len(out.ExitHealth) != 2 {
		t.Fatalf("want 2 exit-health entries, got %d", len(out.ExitHealth))
	}
	de := out.ExitHealth[0]
	if de.Name != "exit-de-1" || !de.Alive || de.Delay != 42*time.Millisecond || !de.Selected || !de.LastTest.Equal(time.Unix(1000, 0).UTC()) {
		t.Fatalf("exit-de-1 round-trip mismatch: %+v", de)
	}
	if out.ExitHealth[1].Alive {
		t.Fatalf("exit-nl-1 should be down")
	}
}

// PublicTCPPorts must survive the wire intact: the agent's firewall renderer is
// the only thing standing between the manifest and an nftables accept rule, so a
// silently dropped field would leave a "configured" port closed with no error.
func TestFirewallPublicTCPPortsRoundTrip(t *testing.T) {
	in := domain.NodeSpec{
		Role: domain.RoleMaster,
		Firewall: domain.FirewallSpec{
			WGPort:         51820,
			PublicTCPPorts: []int{80, 443},
		},
	}
	got := SpecFromProto(SpecToProto(in))
	if len(got.Firewall.PublicTCPPorts) != 2 ||
		got.Firewall.PublicTCPPorts[0] != 80 || got.Firewall.PublicTCPPorts[1] != 443 {
		t.Errorf("PublicTCPPorts round-trip = %v, want [80 443]", got.Firewall.PublicTCPPorts)
	}
}

// An absent list must stay absent rather than becoming an empty non-nil slice —
// the two are equivalent for the renderer, but a spurious diff would show up in
// the operator-facing spec preview.
func TestFirewallPublicTCPPortsEmptyRoundTrip(t *testing.T) {
	got := SpecFromProto(SpecToProto(domain.NodeSpec{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820},
	}))
	if got.Firewall.PublicTCPPorts != nil {
		t.Errorf("PublicTCPPorts = %v, want nil", got.Firewall.PublicTCPPorts)
	}
}

func TestFirewallProtoRoundTripPublicUDPPorts(t *testing.T) {
	in := domain.NodeSpec{
		Role: domain.RoleMaster,
		Firewall: domain.FirewallSpec{
			WGPort:         51820,
			PublicUDPPorts: []int{9994, 500},
		},
	}
	out := SpecFromProto(SpecToProto(in))
	if len(out.Firewall.PublicUDPPorts) != 2 {
		t.Fatalf("PublicUDPPorts = %v, want 2 entries", out.Firewall.PublicUDPPorts)
	}
	// Order is kept as is: normalising it is the renderer's job, not the wire's.
	if out.Firewall.PublicUDPPorts[0] != 9994 || out.Firewall.PublicUDPPorts[1] != 500 {
		t.Fatalf("PublicUDPPorts = %v, want [9994 500]", out.Firewall.PublicUDPPorts)
	}
}

// An empty list must not turn into non-nil on the other side: otherwise
// "field absent" and "field empty" become different specs and cause
// spurious drift on every pass.
func TestFirewallProtoRoundTripPublicUDPPortsEmpty(t *testing.T) {
	got := SpecFromProto(SpecToProto(domain.NodeSpec{
		Role:     domain.RoleExit,
		Firewall: domain.FirewallSpec{WGPort: 51820},
	}))
	if got.Firewall.PublicUDPPorts != nil {
		t.Errorf("PublicUDPPorts = %v, want nil", got.Firewall.PublicUDPPorts)
	}
}
