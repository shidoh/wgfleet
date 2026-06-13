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
		{
			name:    "egress chain with unimplemented method",
			mutate:  func(s *NodeSpec) { s.EgressChain = []EgressMethod{EgressWARP, EgressReality} },
			wantErr: "invalid/unimplemented method",
		},
		{
			name:    "egress chain head must equal preferred",
			mutate:  func(s *NodeSpec) { s.EgressChain = []EgressMethod{EgressDirect, EgressWARP} }, // Egress is warp
			wantErr: "must equal the preferred egress",
		},
		{
			name:   "valid egress chain",
			mutate: func(s *NodeSpec) { s.EgressChain = []EgressMethod{EgressWARP, EgressDirect} },
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

func TestEgressChainHelpers(t *testing.T) {
	// Explicit chain is returned as-is.
	chained := NodeSpec{Egress: EgressWARP, EgressChain: []EgressMethod{EgressWARP, EgressDirect}}
	if got := chained.EgressMethods(); len(got) != 2 || got[0] != EgressWARP || got[1] != EgressDirect {
		t.Errorf("EgressMethods = %v, want [warp direct]", got)
	}
	if !chained.EgressChainHas(EgressDirect) || !chained.EgressChainHas(EgressWARP) {
		t.Error("chain should contain both warp and direct")
	}

	// No chain ⇒ single-entry [Egress].
	single := NodeSpec{Egress: EgressWARP}
	if got := single.EgressMethods(); len(got) != 1 || got[0] != EgressWARP {
		t.Errorf("EgressMethods without chain = %v, want [warp]", got)
	}
	if single.EgressChainHas(EgressDirect) {
		t.Error("a warp-only node must not report direct as a candidate")
	}

	// No egress at all ⇒ empty.
	if got := (NodeSpec{}).EgressMethods(); got != nil {
		t.Errorf("empty spec EgressMethods = %v, want nil", got)
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
