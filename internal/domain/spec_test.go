package domain

import (
	"strings"
	"testing"
)

func validExitSpec() NodeSpec {
	return NodeSpec{
		Role:   RoleExit,
		Egress: EgressWARP,
		WGServer: WGServerSpec{
			ListenPort:  51820,
			AddressPool: "10.81.0.0/24",
			Address:     "10.81.0.1",
			MTU:         1380,
		},
		Peers: []PeerSpec{
			{
				Name:       "master-xa-1",
				PublicKey:  "abc",
				AllowedIPs: []string{"10.81.0.2/32"},
			},
		},
	}
}

func TestNodeSpecValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*NodeSpec)
		wantErr string
	}{
		{name: "valid exit spec", mutate: func(*NodeSpec) {}},
		{
			name:    "bad role",
			mutate:  func(s *NodeSpec) { s.Role = "router" },
			wantErr: "invalid role",
		},
		{
			name:    "exit with bad egress",
			mutate:  func(s *NodeSpec) { s.Egress = "magic" },
			wantErr: "invalid egress",
		},
		{
			name:    "port out of range",
			mutate:  func(s *NodeSpec) { s.WGServer.ListenPort = 70000 },
			wantErr: "out of range",
		},
		{
			name:    "missing address pool",
			mutate:  func(s *NodeSpec) { s.WGServer.AddressPool = "" },
			wantErr: "address pool",
		},
		{
			name:    "mtu too low",
			mutate:  func(s *NodeSpec) { s.WGServer.MTU = 1000 },
			wantErr: "MTU",
		},
		{
			name:    "peer without pubkey",
			mutate:  func(s *NodeSpec) { s.Peers[0].PublicKey = "" },
			wantErr: "missing public key",
		},
		{
			name:    "peer without allowed ips",
			mutate:  func(s *NodeSpec) { s.Peers[0].AllowedIPs = nil },
			wantErr: "no allowed IPs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validExitSpec()
			tt.mutate(&s)
			err := s.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestParseRole(t *testing.T) {
	if _, err := ParseRole("master"); err != nil {
		t.Fatalf("master should parse: %v", err)
	}
	if _, err := ParseRole("nonsense"); err == nil {
		t.Fatal("nonsense should not parse")
	}
}
