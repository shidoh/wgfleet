package domain

import (
	"strings"
	"testing"
)

// Two well-formed, distinct WireGuard public keys. The domain only checks the
// shape of a key, so any valid base64 32-byte value serves.
const (
	testClientPub1 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	testClientPub2 = "2rDXqPqGSJTGRPSaG9jZQMkNFSpsRDIWTuUvBTIBEB8="
)

func validClientWGSpec() ClientWGSpec {
	return ClientWGSpec{
		ListenPort:    443,
		AddressPool:   "10.8.0.0/24",
		ServerAddress: "10.8.0.1",
		MTU:           1280,
		DNS:           []string{"10.8.0.1"},
		AllowedIPs:    []string{"0.0.0.0/0"},
		Backend:       ClientWGBackendKernel,
		Clients: []WGClientPeer{
			{Name: "laptop", PublicKey: testClientPub1, Address: "10.8.0.2/32"},
		},
	}
}

func TestClientWGSpecValidateAcceptsMinimal(t *testing.T) {
	if err := validClientWGSpec().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// An empty backend is the unset case and must resolve to the kernel default
// rather than being rejected — an operator who never touched the knob still
// gets a working interface.
func TestClientWGSpecValidateAcceptsUnsetBackend(t *testing.T) {
	s := validClientWGSpec()
	s.Backend = ""
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() with unset backend = %v, want nil", err)
	}
	if got := s.ResolvedBackend(); got != ClientWGBackendKernel {
		t.Fatalf("ResolvedBackend() = %q, want %q", got, ClientWGBackendKernel)
	}
}

func TestClientWGSpecValidateRejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ClientWGSpec)
		wantErr string
	}{
		{
			name:    "port zero",
			mutate:  func(s *ClientWGSpec) { s.ListenPort = 0 },
			wantErr: "listen port",
		},
		{
			name:    "port out of range",
			mutate:  func(s *ClientWGSpec) { s.ListenPort = 70000 },
			wantErr: "listen port",
		},
		{
			name:    "malformed pool",
			mutate:  func(s *ClientWGSpec) { s.AddressPool = "10.8.0.0/33" },
			wantErr: "address pool",
		},
		{
			name:    "server address outside pool",
			mutate:  func(s *ClientWGSpec) { s.ServerAddress = "10.9.0.1" },
			wantErr: "server address",
		},
		{
			name:    "client address outside pool",
			mutate:  func(s *ClientWGSpec) { s.Clients[0].Address = "10.9.0.2/32" },
			wantErr: "outside the pool",
		},
		{
			name: "duplicate client address",
			mutate: func(s *ClientWGSpec) {
				s.Clients = append(s.Clients, WGClientPeer{
					Name: "phone", PublicKey: testClientPub2, Address: "10.8.0.2/32"})
			},
			wantErr: "duplicate client address",
		},
		{
			name: "duplicate client name",
			mutate: func(s *ClientWGSpec) {
				s.Clients = append(s.Clients, WGClientPeer{
					Name: "laptop", PublicKey: testClientPub2, Address: "10.8.0.3/32"})
			},
			wantErr: "duplicate client name",
		},
		{
			name:    "client collides with the server address",
			mutate:  func(s *ClientWGSpec) { s.Clients[0].Address = "10.8.0.1/32" },
			wantErr: "server address",
		},
		{
			name:    "empty public key",
			mutate:  func(s *ClientWGSpec) { s.Clients[0].PublicKey = "" },
			wantErr: "public key",
		},
		{
			name:    "malformed public key",
			mutate:  func(s *ClientWGSpec) { s.Clients[0].PublicKey = "not-a-key" },
			wantErr: "public key",
		},
		{
			name:    "empty client name",
			mutate:  func(s *ClientWGSpec) { s.Clients[0].Name = "" },
			wantErr: "name",
		},
		{
			// The data plane is IPv4-only: an ::/0 in the client's AllowedIPs routes
			// IPv6 into a dead tunnel and stalls dual-stack traffic.
			name:    "ipv6 default route in allowed ips",
			mutate:  func(s *ClientWGSpec) { s.AllowedIPs = []string{"0.0.0.0/0", "::/0"} },
			wantErr: "IPv6",
		},
		{
			name:    "malformed allowed ips",
			mutate:  func(s *ClientWGSpec) { s.AllowedIPs = []string{"0.0.0.0/0", "nonsense"} },
			wantErr: "allowed IPs",
		},
		{
			name:    "unknown backend",
			mutate:  func(s *ClientWGSpec) { s.Backend = "wireguard-go" },
			wantErr: "backend",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := validClientWGSpec()
			tc.mutate(&s)
			err := s.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// A spec with no clients is valid: the interface still comes up, it just has no
// peers yet. Mirrors the client-VLESS inbound with no issued credentials.
func TestClientWGSpecValidateAcceptsNoClients(t *testing.T) {
	s := validClientWGSpec()
	s.Clients = nil
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() with no clients = %v, want nil", err)
	}
}

// PeersOf drops muted accounts: the peer disappears from the interface while the
// credential (and the user's config) stays valid.
func TestPeersOfSkipsDisabled(t *testing.T) {
	clients := []WGClient{
		{ID: "a", Name: "laptop", Address: "10.8.0.2/32", PublicKey: testClientPub1, PrivateKey: "priv-a", Enabled: true},
		{ID: "b", Name: "phone", Address: "10.8.0.3/32", PublicKey: testClientPub2, PrivateKey: "priv-b", Enabled: false},
	}
	peers := PeersOf(clients)
	if len(peers) != 1 {
		t.Fatalf("PeersOf() returned %d peers, want 1: %+v", len(peers), peers)
	}
	got := peers[0]
	if got.Name != "laptop" || got.PublicKey != testClientPub1 || got.Address != "10.8.0.2/32" {
		t.Fatalf("PeersOf() = %+v, want the enabled laptop peer", got)
	}
}

// The peer view is what travels to the node. It must be structurally incapable
// of carrying a client's private key (spec §3.1, §9) — asserted by rendering a
// peer built from a credential that has one and checking every field.
func TestWGClientPeerCarriesNoPrivateKey(t *testing.T) {
	c := WGClient{
		ID: "a", Name: "laptop", Address: "10.8.0.2/32",
		PublicKey: testClientPub1, PrivateKey: "SUPER-SECRET-PRIVATE-KEY",
		PresharedKey: "psk", Enabled: true,
	}
	peers := PeersOf([]WGClient{c})
	if len(peers) != 1 {
		t.Fatalf("PeersOf() returned %d peers, want 1", len(peers))
	}
	for _, field := range []string{peers[0].Name, peers[0].PublicKey, peers[0].Address, peers[0].PresharedKey} {
		if strings.Contains(field, "SECRET") {
			t.Fatalf("peer field %q leaks the client private key", field)
		}
	}
}

// NodeSpec.Validate is the controller's only spec-wide gate and the agent's
// fail-safe: a spec it rejects is never applied. The client interface must be
// covered by it on its own — an earlier version nested the check inside the
// client-VLESS branch, so a master that ran WG clients without VLESS shipped an
// unvalidated interface, and the injection guard lived on one layer.
func TestNodeSpecValidatesClientWGWithoutVLESS(t *testing.T) {
	spec := NodeSpec{
		Role:     RoleMaster,
		Egress:   EgressDirect,
		WGServer: WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24", Address: "10.80.0.1", MTU: 1360},
		Master: &MasterSpec{
			// No ClientVLESS: the ordinary shape for this migration.
			ClientWG: &ClientWGSpec{
				ListenPort:    443,
				AddressPool:   "10.80.0.0/24",
				ServerAddress: "10.80.0.1",
				AllowedIPs:    []string{"0.0.0.0/0"},
				Clients: []WGClientPeer{{
					// A name carrying a newline: rendered verbatim, this extends the
					// interface config with a peer of somebody else's choosing.
					Name:      "laptop\n[Peer]\nAllowedIPs = 0.0.0.0/0",
					PublicKey: testClientPub1,
					Address:   "10.80.0.2/32",
				}},
			},
		},
	}
	err := spec.Validate()
	if err == nil {
		t.Fatal("NodeSpec.Validate() accepted a client interface with an injectable name")
	}
	if !strings.Contains(err.Error(), "client wg") {
		t.Fatalf("NodeSpec.Validate() = %v, want the client wg spec named", err)
	}
}

func TestClientWGSpecKeepaliveValidation(t *testing.T) {
	for _, ok := range []string{"", "25", "5", "120", "15-25", "20-20"} {
		s := validClientWGSpec()
		s.Keepalive = ok
		if err := s.Validate(); err != nil {
			t.Errorf("keepalive %q should be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"nonsense", "0", "4", "121", "25-15", "-5", "25-", "1e3"} {
		s := validClientWGSpec()
		s.Keepalive = bad
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), "keepalive") {
			t.Errorf("keepalive %q should fail validation, got %v", bad, err)
		}
	}
}
