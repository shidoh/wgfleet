package wg

import (
	"strconv"
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

// The <c> and <t> CPS tags are kernel-module features that userspace
// WireGuard-Go cannot parse. domain.ValidateUserspace exists to catch them, but
// it was only ever wired into the mihomo renderer — so a client leg on the
// userspace backend would render a config its own data plane chokes on.
func TestRenderClientInterfaceRejectsKernelOnlySignaturesOnUserspace(t *testing.T) {
	s := clientSpec()
	s.Backend = domain.ClientWGBackendUserspace
	s.AWG.Local.I1 = "<b 0xaa><c>"

	_, err := RenderClientInterface(ClientInterfaceInput{Spec: s, PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="})
	if err == nil {
		t.Fatal("a <c> tag was rendered into a userspace client interface")
	}
	if !strings.Contains(err.Error(), "userspace") {
		t.Fatalf("error should name the userspace restriction, got: %v", err)
	}
}

// The same signature on the kernel backend is legitimate — that is the whole
// reason the two validators differ.
func TestRenderClientInterfaceAllowsKernelOnlySignaturesOnKernel(t *testing.T) {
	s := clientSpec()
	s.Backend = domain.ClientWGBackendKernel
	s.AWG.Local.I1 = "<b 0xaa><c>"

	if _, err := RenderClientInterface(ClientInterfaceInput{Spec: s, PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="}); err != nil {
		t.Fatalf("kernel backend rejected a kernel-only signature: %v", err)
	}
}

// The far end of this leg is somebody's phone, which is userspace WireGuard-Go
// whatever the SERVER runs on. So a client config is held to the userspace rule
// unconditionally — a kernel-backed interface may legitimately use <c>/<t> in its
// own decoy while the config it hands out must not.
func TestRenderClientConfigRejectsKernelOnlySignatures(t *testing.T) {
	s := clientSpec()
	s.Backend = domain.ClientWGBackendKernel
	s.ClientAWGLocal = &domain.AWGLocal{Jc: 6, Jmin: 45, Jmax: 75, I1: "<b 0xbb><t>"}

	_, err := RenderClientConfig(ClientConfigInput{
		Spec:   s,
		Client: domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="},
		ServerPublicKey: "cHViLXNlcnZlci0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		Endpoint:        "203.0.113.1:443",
	})
	if err == nil {
		t.Fatal("a <t> tag was rendered into a config for a userspace client")
	}
	if !strings.Contains(err.Error(), "userspace") {
		t.Fatalf("error should name the userspace restriction, got: %v", err)
	}
}

// An unset keepalive keeps the value every WireGuard deployment on earth uses.
// Changing that default silently would alter the traffic shape of every client
// on an ordinary upgrade.
func TestClientKeepaliveDefaults(t *testing.T) {
	if got := ClientKeepaliveFor("", "any-id"); got != ClientKeepaliveSeconds {
		t.Fatalf("ClientKeepaliveFor(\"\") = %d, want %d", got, ClientKeepaliveSeconds)
	}
}

func TestClientKeepaliveFixedValue(t *testing.T) {
	if got := ClientKeepaliveFor("18", "any-id"); got != 18 {
		t.Fatalf("ClientKeepaliveFor(\"18\") = %d, want 18", got)
	}
}

// A band gives each credential its OWN interval. The point is to break the
// fleet-wide lockstep — every client of ours beaconing at the same second is a
// correlation handle joining them to each other — so the value must depend on the
// credential and must be stable, because the config is re-rendered on every
// portal visit and a value that moved would hand the user a different config each
// time they opened their link.
func TestClientKeepaliveBandIsPerClientAndStable(t *testing.T) {
	const band = "15-25"
	seen := map[int]int{}
	for i := 0; i < 200; i++ {
		id := "cred-" + strconv.Itoa(i)
		got := ClientKeepaliveFor(band, id)
		if got < 15 || got > 25 {
			t.Fatalf("id %q: keepalive %d outside the band %s", id, got, band)
		}
		if again := ClientKeepaliveFor(band, id); again != got {
			t.Fatalf("id %q: keepalive moved between renders, %d then %d", id, got, again)
		}
		seen[got]++
	}
	if len(seen) < 5 {
		t.Fatalf("a band of 11 values produced only %d distinct intervals across 200 clients: %v", len(seen), seen)
	}
}

func TestRenderClientConfigUsesTheDerivedKeepalive(t *testing.T) {
	s := clientSpec()
	s.Keepalive = "19"
	out, err := RenderClientConfig(ClientConfigInput{
		Spec:   s,
		Client: domain.WGClient{ID: "cred-1", Name: "laptop", Address: "10.80.0.2/32", PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="},
		ServerPublicKey: "cHViLXNlcnZlci0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		Endpoint:        "203.0.113.1:443",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "PersistentKeepalive = 19") {
		t.Fatalf("config did not carry the configured keepalive:\n%s", out)
	}
}

// Each client emits its OWN junk and signature profile. With one shared profile
// every client of a master looked identical on the wire, so an observer who
// picked out one of them had a handle that joined it to the rest.
func TestClientConfigsGetTheirOwnDecoy(t *testing.T) {
	s := clientSpec()
	render := func(id, pub string) string {
		out, err := RenderClientConfig(ClientConfigInput{
			Spec: s,
			Client: domain.WGClient{
				ID: id, Name: id, Address: "10.80.0.2/32",
				PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=", PublicKey: pub,
			},
			ServerPublicKey: "cHViLXNlcnZlci0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
			Endpoint:        "203.0.113.1:443",
		})
		if err != nil {
			t.Fatalf("render %s: %v", id, err)
		}
		return out
	}
	line := func(cfg, key string) string {
		for _, l := range strings.Split(cfg, "\n") {
			if strings.HasPrefix(l, key+" = ") {
				return l
			}
		}
		return ""
	}

	a := render("a", testClientPubA)
	b := render("b", testClientPubB)

	for _, key := range []string{"Jc", "Jmin", "Jmax", "I1"} {
		if line(a, key) == line(b, key) {
			t.Errorf("two clients share %s (%q) — their traffic is correlatable", key, line(a, key))
		}
	}
	// The shared half MUST still match, or neither config completes a handshake.
	for _, key := range []string{"S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
		if line(a, key) != line(b, key) {
			t.Errorf("clients disagree on the shared parameter %s: %q vs %q", key, line(a, key), line(b, key))
		}
	}
	// Stability: the config is re-rendered on every portal visit, and a value that
	// moved would hand the same person a different config each time.
	if again := render("a", testClientPubA); again != a {
		t.Error("re-rendering the same client produced a different config")
	}
}

// The decoy must never carry the kernel-only CPS tags: the far end is an app on
// userspace WireGuard-Go.
func TestClientDecoyStaysUserspaceSafe(t *testing.T) {
	for i, pub := range []string{testClientPubA, testClientPubB} {
		local := DeriveAWGLocal(clientDecoyPrefix+pub, false)
		p := domain.AWGParams{Shared: clientSpec().AWG.Shared, Local: local}
		if err := p.ValidateUserspace(); err != nil {
			t.Errorf("client %d decoy is not userspace-safe: %v", i, err)
		}
	}
}

const (
	testClientPubA = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	testClientPubB = "2rDXqPqGSJTGRPSaG9jZQMkNFSpsRDIWTuUvBTIBEB8="
)
