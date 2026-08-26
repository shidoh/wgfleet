package wg

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func clientSpec() domain.ClientWGSpec {
	return domain.ClientWGSpec{
		ListenPort:    443,
		AddressPool:   "10.80.0.0/24",
		ServerAddress: "10.80.0.1",
		MTU:           1360,
		DNS:           []string{"10.80.0.1"},
		AllowedIPs:    []string{"0.0.0.0/0"},
		AWG: &domain.AWGParams{
			Shared: domain.AWGShared{
				S1: 30, S2: 40, S3: 20, S4: 26,
				H1: domain.AWGHeader{Min: 1, Max: 4},
				H2: domain.AWGHeader{Min: 5, Max: 8},
				H3: domain.AWGHeader{Min: 9, Max: 12},
				H4: domain.AWGHeader{Min: 13, Max: 16},
			},
			Local: domain.AWGLocal{Jc: 4, Jmin: 40, Jmax: 70, I1: "<b 0xaa>"},
		},
		ClientAWGLocal: &domain.AWGLocal{Jc: 6, Jmin: 45, Jmax: 75, I1: "<b 0xbb>"},
		Clients: []domain.WGClientPeer{
			{Name: "laptop", PublicKey: "cHViLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA=", Address: "10.80.0.2/32", PresharedKey: "cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA="},
			{Name: "phone", PublicKey: "cHViLXBob25lLTAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", Address: "10.80.0.3/32"},
		},
	}
}

func TestRenderClientInterface(t *testing.T) {
	got, err := RenderClientInterface(ClientInterfaceInput{
		Spec:       clientSpec(),
		PrivateKey: "c2VydmVyLXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=",
	})
	if err != nil {
		t.Fatalf("RenderClientInterface() error = %v", err)
	}

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = c2VydmVyLXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=",
		"Address = 10.80.0.1/24",
		"ListenPort = 443",
		"MTU = 1360",
		// The interface emits the SERVER end's local decoy, never the client's.
		"Jc = 4",
		"S4 = 26",
		"H1 = 1-4",
		"I1 = <b 0xaa>",
		// Peers.
		"# laptop",
		"PublicKey = cHViLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		"PresharedKey = cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		"AllowedIPs = 10.80.0.2/32",
		"# phone",
		"AllowedIPs = 10.80.0.3/32",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered interface missing %q:\n%s", want, got)
		}
	}

	// The client's own decoy must never leak into the server interface.
	if strings.Contains(got, "<b 0xbb>") {
		t.Error("server interface carries the CLIENT-end signature packets")
	}
	// Clients dial us, so no peer may carry an endpoint or a keepalive.
	if strings.Contains(got, "Endpoint") || strings.Contains(got, "PersistentKeepalive") {
		t.Errorf("server interface must not dial its clients:\n%s", got)
	}
	// The phone has no PSK: the key must be omitted, not emitted empty (an empty
	// value is a parse error on the node, not a "no preshared key").
	phoneBlock := got[strings.Index(got, "# phone"):]
	if strings.Contains(phoneBlock, "PresharedKey") {
		t.Errorf("peer without a preshared key emitted the key anyway:\n%s", phoneBlock)
	}
}

func TestRenderClientInterfaceRejectsIncomplete(t *testing.T) {
	if _, err := RenderClientInterface(ClientInterfaceInput{Spec: clientSpec()}); err == nil {
		t.Error("rendering without a private key should fail")
	}
	bad := clientSpec()
	bad.AddressPool = "nonsense"
	if _, err := RenderClientInterface(ClientInterfaceInput{Spec: bad, PrivateKey: "k"}); err == nil {
		t.Error("rendering with a malformed pool should fail")
	}
}

// A managed interface with no issued credentials is valid: it comes up and
// authenticates no one, exactly like the client VLESS inbound with no clients.
func TestRenderClientInterfaceWithNoPeers(t *testing.T) {
	spec := clientSpec()
	spec.Clients = nil
	got, err := RenderClientInterface(ClientInterfaceInput{Spec: spec, PrivateKey: "k"})
	if err != nil {
		t.Fatalf("RenderClientInterface() error = %v", err)
	}
	if strings.Contains(got, "[Peer]") {
		t.Errorf("interface with no credentials rendered a peer:\n%s", got)
	}
}

func TestRenderClientConfig(t *testing.T) {
	got, err := RenderClientConfig(ClientConfigInput{
		Spec:            clientSpec(),
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PrivateKey: "Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=", PresharedKey: "cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA="},
		ServerPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
		Endpoint:        "203.0.113.1:443",
	})
	if err != nil {
		t.Fatalf("RenderClientConfig() error = %v", err)
	}

	for _, want := range []string{
		"PrivateKey = Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=",
		"Address = 10.80.0.2/32",
		"DNS = 10.80.0.1",
		"MTU = 1360",
		// Shared params must match the server's interface exactly.
		"S4 = 26",
		"H3 = 9-12",
		// The CLIENT's own decoy, not the server's.
		"Jc = 6",
		"I1 = <b 0xbb>",
		"[Peer]",
		"PublicKey = c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
		"PresharedKey = cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 203.0.113.1:443",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("client config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<b 0xaa>") {
		t.Error("client config carries the SERVER-end signature packets")
	}
	// The IPv4-only data plane: an ::/0 must never appear in a generated config.
	if strings.Contains(got, "::/0") {
		t.Errorf("client config routes IPv6 into an IPv4-only tunnel:\n%s", got)
	}
}

func TestRenderClientConfigRejectsIncomplete(t *testing.T) {
	full := ClientConfigInput{
		Spec:            clientSpec(),
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PrivateKey: "k"},
		ServerPublicKey: "pub",
		Endpoint:        "203.0.113.1:443",
	}
	tests := map[string]func(*ClientConfigInput){
		"no client private key": func(in *ClientConfigInput) { in.Client.PrivateKey = "" },
		"no server public key":  func(in *ClientConfigInput) { in.ServerPublicKey = "" },
		"no endpoint":           func(in *ClientConfigInput) { in.Endpoint = "" },
		"no address":            func(in *ClientConfigInput) { in.Client.Address = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			in := full
			mutate(&in)
			if _, err := RenderClientConfig(in); err == nil {
				t.Fatal("RenderClientConfig() = nil error, want a failure")
			}
		})
	}
}

// Both renderers must keep their secrets out of plan/dry-run output.
func TestRedactConfigCoversClientRenders(t *testing.T) {
	iface, err := RenderClientInterface(ClientInterfaceInput{Spec: clientSpec(), PrivateKey: "SERVERSECRET"})
	if err != nil {
		t.Fatalf("render interface: %v", err)
	}
	if red := RedactConfig(iface); strings.Contains(red, "SERVERSECRET") ||
		strings.Contains(red, "cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA=") {
		t.Errorf("redacted interface still leaks a secret:\n%s", red)
	}
	cfg, err := RenderClientConfig(ClientConfigInput{
		Spec:            clientSpec(),
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PrivateKey: "CLIENTSECRET"},
		ServerPublicKey: "pub",
		Endpoint:        "203.0.113.1:443",
	})
	if err != nil {
		t.Fatalf("render config: %v", err)
	}
	if red := RedactConfig(cfg); strings.Contains(red, "CLIENTSECRET") {
		t.Errorf("redacted client config still leaks the private key:\n%s", red)
	}
}
