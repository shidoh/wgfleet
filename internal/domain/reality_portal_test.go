package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// The frozen golden specs are json.MarshalIndent(NodeSpec) of fleets that never
// use the exit-initiated REALITY mode; a nil pointer without omitempty would
// write "null" and change every one of them.
func TestRealityReverseFieldsOmittedWhenUnset(t *testing.T) {
	for name, v := range map[string]any{
		"RealityServerSpec": RealityServerSpec{ListenPort: 443},
		"RealityTunnel":     RealityTunnel{UUID: "u"},
		"MasterSpec":        MasterSpec{RedirPort: 7892},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"Bridge", "Reverse", "RealityPortal"} {
			if strings.Contains(string(b), `"`+field+`"`) {
				t.Errorf("%s serialises %q while unset: %s", name, field, b)
			}
		}
	}
}

func TestRealityReverseFieldsRoundTrip(t *testing.T) {
	in := NodeSpec{
		Reality: &RealityServerSpec{Bridge: &RealityBridgeSpec{Portals: []RealityPortalPeer{validPortalPeer()}}},
		Master: &MasterSpec{
			ExitTunnels:   []ExitTunnel{{Name: "exit-a", Reality: &RealityTunnel{Reverse: true}}},
			RealityPortal: ptr(validPortalSpec()),
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out NodeSpec
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Reality.Bridge == nil || len(out.Reality.Bridge.Portals) != 1 ||
		!out.Master.ExitTunnels[0].Reality.Reverse || out.Master.RealityPortal == nil ||
		out.Master.RealityPortal.Clients[0].Exit != "exit-a" {
		t.Fatalf("round trip lost reverse fields: %s", b)
	}
}

func ptr[T any](v T) *T { return &v }

func validPortalSpec() RealityPortalSpec {
	return RealityPortalSpec{
		ListenPort: 48123,
		SocksPort:  RealityPortalSocksPort,
		ServerName: "www.python.org",
		Dest:       "www.python.org:443",
		Image:      "ghcr.io/xtls/xray-core:26.6.22",
		Clients:    []RealityPortalClient{{Exit: "exit-a", UUID: "11111111-2222-3333-4444-555555555555", ShortID: "0a1b"}},
	}
}

func validPortalPeer() RealityPortalPeer {
	return RealityPortalPeer{
		Master:     "master-a",
		Address:    "203.0.113.1:48123",
		PublicKey:  "pub",
		UUID:       "11111111-2222-3333-4444-555555555555",
		ShortID:    "0a1b",
		ServerName: "www.python.org",
	}
}

func TestRealityPortalValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*RealityPortalSpec)
		wantErr string
	}{
		{name: "valid", mutate: func(*RealityPortalSpec) {}},
		{name: "no clients is valid", mutate: func(s *RealityPortalSpec) { s.Clients = nil }},
		{name: "port zero", mutate: func(s *RealityPortalSpec) { s.ListenPort = 0 }, wantErr: "listen port"},
		{name: "port too high", mutate: func(s *RealityPortalSpec) { s.ListenPort = 70000 }, wantErr: "listen port"},
		{name: "socks port", mutate: func(s *RealityPortalSpec) { s.SocksPort = -1 }, wantErr: "socks port"},
		{name: "no sni", mutate: func(s *RealityPortalSpec) { s.ServerName = "" }, wantErr: "server name"},
		{name: "no dest", mutate: func(s *RealityPortalSpec) { s.Dest = "" }, wantErr: "dest"},
		{name: "no image", mutate: func(s *RealityPortalSpec) { s.Image = "" }, wantErr: "image"},
		{name: "client without exit", mutate: func(s *RealityPortalSpec) { s.Clients[0].Exit = "" }, wantErr: "exit"},
		{name: "client without uuid", mutate: func(s *RealityPortalSpec) { s.Clients[0].UUID = "" }, wantErr: "UUID"},
		{name: "odd short id", mutate: func(s *RealityPortalSpec) { s.Clients[0].ShortID = "abc" }, wantErr: "short-id"},
		{name: "non-hex short id", mutate: func(s *RealityPortalSpec) { s.Clients[0].ShortID = "zz" }, wantErr: "short-id"},
		{name: "empty short id", mutate: func(s *RealityPortalSpec) { s.Clients[0].ShortID = "" }, wantErr: "short-id"},
		{
			name:    "duplicate exit",
			mutate:  func(s *RealityPortalSpec) { s.Clients = append(s.Clients, s.Clients[0]) },
			wantErr: "duplicate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validPortalSpec()
			s.Clients = append([]RealityPortalClient(nil), s.Clients...)
			tt.mutate(&s)
			assertErr(t, s.Validate(), tt.wantErr)
		})
	}
}

func TestRealityBridgeValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*RealityBridgeSpec)
		wantErr string
	}{
		{name: "valid", mutate: func(*RealityBridgeSpec) {}},
		{name: "no portals", mutate: func(b *RealityBridgeSpec) { b.Portals = nil }, wantErr: "no portal"},
		{name: "no master", mutate: func(b *RealityBridgeSpec) { b.Portals[0].Master = "" }, wantErr: "master"},
		{name: "address without port", mutate: func(b *RealityBridgeSpec) { b.Portals[0].Address = "203.0.113.1" }, wantErr: "address"},
		{name: "address is a name", mutate: func(b *RealityBridgeSpec) { b.Portals[0].Address = "m.example:1" }, wantErr: "address"},
		{name: "no public key", mutate: func(b *RealityBridgeSpec) { b.Portals[0].PublicKey = "" }, wantErr: "public key"},
		{name: "no uuid", mutate: func(b *RealityBridgeSpec) { b.Portals[0].UUID = "" }, wantErr: "UUID"},
		{name: "bad short id", mutate: func(b *RealityBridgeSpec) { b.Portals[0].ShortID = "x" }, wantErr: "short-id"},
		{name: "no sni", mutate: func(b *RealityBridgeSpec) { b.Portals[0].ServerName = "" }, wantErr: "server name"},
		{
			name:    "duplicate master",
			mutate:  func(b *RealityBridgeSpec) { b.Portals = append(b.Portals, b.Portals[0]) },
			wantErr: "duplicate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := RealityBridgeSpec{Portals: []RealityPortalPeer{validPortalPeer()}}
			tt.mutate(&b)
			assertErr(t, b.Validate(), tt.wantErr)
		})
	}
}

func TestRealityPortalPeerFingerprintDefaultsToChrome(t *testing.T) {
	p := validPortalPeer()
	if got := p.ResolvedFingerprint(); got != "chrome" {
		t.Errorf("default fingerprint = %q, want chrome", got)
	}
	p.Fingerprint = "firefox"
	if got := p.ResolvedFingerprint(); got != "firefox" {
		t.Errorf("explicit fingerprint = %q, want firefox", got)
	}
}

func TestReverseTagNamesThePeer(t *testing.T) {
	if got := ReverseTag("vn0"); got != "r-vn0" {
		t.Errorf("ReverseTag = %q, want r-vn0", got)
	}
}

func TestRealityPortalResolvedSocksPort(t *testing.T) {
	if got := (RealityPortalSpec{}).ResolvedSocksPort(); got != RealityPortalSocksPort {
		t.Errorf("default socks port = %d, want %d", got, RealityPortalSocksPort)
	}
	if got := (RealityPortalSpec{SocksPort: 1}).ResolvedSocksPort(); got != 1 {
		t.Errorf("explicit socks port = %d, want 1", got)
	}
}

func assertErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want containing %q", err, want)
	}
}
