package clientcfg

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

type stubSource struct {
	nodes   map[string]domain.Node
	spec    domain.NodeSpec
	clients map[string][]domain.WGClient
	listErr error
}

func (s stubSource) GetNode(_ context.Context, id string) (domain.Node, error) {
	n, ok := s.nodes[id]
	if !ok {
		return domain.Node{}, store.ErrNotFound
	}
	return n, nil
}

func (s stubSource) RenderNodeSpec(context.Context, string) (domain.NodeSpec, error) {
	return s.spec, nil
}

func (s stubSource) ListWGClients(_ context.Context, id string) ([]domain.WGClient, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.clients[id], nil
}

func managedSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{ClientWG: &domain.ClientWGSpec{
			ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1",
			MTU: 1360, DNS: []string{"10.80.0.1"}, AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
}

func source() stubSource {
	return stubSource{
		nodes: map[string]domain.Node{"m1": {
			ID: "m1", Name: "m1", Role: domain.RoleMaster, PublicIP: "203.0.113.1",
			ClientWGPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
		}},
		spec: managedSpec(),
		clients: map[string][]domain.WGClient{"m1": {
			{ID: "abc", Name: "laptop", Address: "10.80.0.2/32",
				PublicKey: "pub", PrivateKey: "Y2xpZW50LWtleQ==", Enabled: true},
		}},
	}
}

func TestBuild(t *testing.T) {
	res, err := Build(context.Background(), source(), "m1", "abc")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if res.Client.Name != "laptop" || res.Master.ID != "m1" {
		t.Fatalf("result = %+v", res)
	}
	for _, want := range []string{"PrivateKey = Y2xpZW50LWtleQ==", "Endpoint = 203.0.113.1:443", "PersistentKeepalive = 25"} {
		if !strings.Contains(res.Config, want) {
			t.Errorf("config missing %q:\n%s", want, res.Config)
		}
	}
	if got := ConfigFileName(res.Client); got != "laptop.conf" {
		t.Errorf("ConfigFileName() = %q", got)
	}
}

func TestBuildFailures(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*stubSource)
		master  string
		client  string
		wantErr string
	}{
		"unknown master": {master: "nope", client: "abc", wantErr: "not found"},
		"unknown client": {master: "m1", client: "zzz", wantErr: "not found"},
		"interface still wg-easy's": {
			mutate:  func(s *stubSource) { s.spec = domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}} },
			master:  "m1",
			client:  "abc",
			wantErr: "not managed",
		},
		"key not published yet": {
			mutate: func(s *stubSource) {
				n := s.nodes["m1"]
				n.ClientWGPublicKey = ""
				s.nodes["m1"] = n
			},
			master: "m1", client: "abc", wantErr: "has not published",
		},
		"no endpoint": {
			mutate: func(s *stubSource) {
				n := s.nodes["m1"]
				n.PublicIP = ""
				s.nodes["m1"] = n
			},
			master: "m1", client: "abc", wantErr: "no public endpoint",
		},
		"store unavailable": {
			mutate: func(s *stubSource) { s.listErr = errors.New("store is down") },
			master: "m1", client: "abc", wantErr: "store is down",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			src := source()
			if tc.mutate != nil {
				tc.mutate(&src)
			}
			_, err := Build(context.Background(), src, tc.master, tc.client)
			if err == nil {
				t.Fatalf("Build() = nil error, want one mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Build() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestFindByID(t *testing.T) {
	src := source()
	src.clients["m2"] = []domain.WGClient{{ID: "def", Name: "phone"}}

	got, err := FindByID(context.Background(), src, []string{"m2", "m1"}, "abc")
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if got != "m1" {
		t.Fatalf("FindByID() = %q, want m1", got)
	}
	if _, err := FindByID(context.Background(), src, []string{"m1", "m2"}, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("FindByID() for an unknown token = %v, want ErrNotFound", err)
	}
}

// The endpoint falls back through the sources in the order an operator would
// expect: the registered public IP first, then what the manifest declared, then
// the address we provisioned the node through.
func TestEndpointHostFallback(t *testing.T) {
	spec := managedSpec()
	spec.Master.Compose.PublicIP = "198.51.100.4"
	node := domain.Node{PublicIP: "203.0.113.1", SSH: domain.SSHTarget{Host: "192.0.2.9"}}

	if got := EndpointHost(node, spec); got != "203.0.113.1" {
		t.Errorf("EndpointHost() = %q, want the registered public IP", got)
	}
	node.PublicIP = ""
	if got := EndpointHost(node, spec); got != "198.51.100.4" {
		t.Errorf("EndpointHost() = %q, want the manifest's public IP", got)
	}
	// The SSH host is deliberately NOT a fallback: it is often the management
	// overlay, and a client profile must never point end users there.
	spec.Master.Compose.PublicIP = ""
	if got := EndpointHost(node, spec); got != "" {
		t.Errorf("EndpointHost() = %q, want empty — the SSH host must not reach a client config", got)
	}
}
