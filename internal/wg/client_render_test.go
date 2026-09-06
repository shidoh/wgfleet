package wg

import (
	"fmt"
	"net/netip"
	"regexp"
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
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA, PrivateKey: "Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=", PresharedKey: "cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA="},
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

		"[Peer]",
		"PublicKey = c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=",
		"PresharedKey = cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 203.0.113.1:443",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("client config missing %q:\n%s", want, got)
		}
	}
	// The keepalive is DERIVED per credential rather than the fleet-wide 25 that
	// used to sit here: one interval shared by every client is a period a passive
	// observer can join our users on. Assert the NAT-safe band, not a literal.
	if m := regexp.MustCompile(`(?m)^PersistentKeepalive = (\d+)$`).FindStringSubmatch(got); m == nil {
		t.Errorf("client config has no PersistentKeepalive:\n%s", got)
	} else {
		n, _ := strconv.Atoi(m[1])
		if n < 15 || n > 28 {
			t.Errorf("PersistentKeepalive = %d, outside the NAT-safe band [15,28]", n)
		}
	}
	// The decoy must be the CLIENT's own, derived from its public key — not the
	// server's, and not a spec field. These two assertions used to read values
	// planted in ClientAWGLocal, which meant they exercised a fallback branch the
	// store makes unreachable rather than the path every real config takes.
	if strings.Contains(got, "<b 0xaa>") || strings.Contains(got, "Jc = 4") {
		t.Errorf("client config carries the SERVER-end decoy:\n%s", got)
	}
	want := clientDecoy(clientSpec(), domain.WGClient{PublicKey: testClientPubA})
	if !strings.Contains(got, fmt.Sprintf("Jc = %d", want.Jc)) ||
		!strings.Contains(got, fmt.Sprintf("Jmin = %d", want.Jmin)) {
		t.Errorf("client config does not carry this credential's derived decoy (want Jc=%d Jmin=%d):\n%s",
			want.Jc, want.Jmin, got)
	}
	// The IPv4-only data plane: an ::/0 must never appear in a generated config.
	if strings.Contains(got, "::/0") {
		t.Errorf("client config routes IPv6 into an IPv4-only tunnel:\n%s", got)
	}
}

func TestRenderClientConfigRejectsIncomplete(t *testing.T) {
	full := ClientConfigInput{
		Spec:            clientSpec(),
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA, PrivateKey: "k"},
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
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA, PrivateKey: "CLIENTSECRET"},
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

// The 3.x header-protection key is the parameter whose whole point is that an
// observer does not have it, and it is written into the same files as the other
// two secrets. The fixture above carries no 3.x block, so it could never have
// caught this — hence a spec that does.
func TestRedactConfigMasksHeaderProtectionKey(t *testing.T) {
	const marker = "SFBLLVNFQ1JFVC1NQVJLRVIAAAAAAAAAAAAAAAAAAAA=" // "HPK-SECRET-MARKER", padded to 32 bytes
	spec := clientSpec()
	awg := *spec.AWG
	awg.Shared.HeaderProtectionKey = marker
	spec.AWG = &awg

	iface, err := RenderClientInterface(ClientInterfaceInput{Spec: spec, PrivateKey: "SERVERSECRET"})
	if err != nil {
		t.Fatalf("render interface: %v", err)
	}
	if !strings.Contains(iface, marker) {
		t.Fatalf("fixture is not exercising the 3.x path — the key never reached the config:\n%s", iface)
	}
	if red := RedactConfig(iface); strings.Contains(red, marker) {
		t.Errorf("redacted interface still leaks the header-protection key:\n%s", red)
	}

	cfg, err := RenderClientConfig(ClientConfigInput{
		Spec:            spec,
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA, PrivateKey: "CLIENTSECRET"},
		ServerPublicKey: "pub",
		Endpoint:        "203.0.113.1:443",
	})
	if err != nil {
		t.Fatalf("render config: %v", err)
	}
	if red := RedactConfig(cfg); strings.Contains(red, marker) {
		t.Errorf("redacted client config still leaks the header-protection key:\n%s", red)
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
// A kernel-only <c>/<t> tag must never reach a client config — the far end is an
// app on WireGuard-Go, which cannot parse them.
//
// This used to be written as "rendering with such a tag returns an error", with
// the tag planted in ClientAWGLocal. That field was only ever read by a branch the
// store makes unreachable, so the test proved nothing about a real config. The
// property is now stronger and structural: the server's own local profile does not
// reach the client at all, because the client's half is DERIVED per credential —
// so plant the tag on the server and assert the config comes out clean anyway.
func TestClientConfigNeverCarriesKernelOnlySignatures(t *testing.T) {
	s := clientSpec()
	s.Backend = domain.ClientWGBackendKernel
	awg := *s.AWG
	awg.Local.I1 = "<b 0xbb><t>"
	awg.Local.I2 = "<c>"
	s.AWG = &awg

	got, err := RenderClientConfig(ClientConfigInput{
		Spec:            s,
		Client:          domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA, PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="},
		ServerPublicKey: "cHViLXNlcnZlci0wMDAwMDAwMDAwMDAwMDAwMDAwMA=",
		Endpoint:        "203.0.113.1:443",
	})
	if err != nil {
		t.Fatalf("a kernel-only tag on the SERVER must not stop a client config rendering: %v", err)
	}
	for _, tag := range []string{"<t>", "<c>"} {
		if strings.Contains(got, tag) {
			t.Errorf("client config carries the kernel-only tag %q:\n%s", tag, got)
		}
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
		Spec:            s,
		Client:          domain.WGClient{ID: "cred-1", Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA, PrivateKey: "cHJpdi0wMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="},
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

	// The per-end unique half: junk decoy plus the QUIC cover packet (I2), whose
	// DCID/SCID/payload sizes are drawn from the client's own seed.
	for _, key := range []string{"Jc", "Jmin", "Jmax", "I2"} {
		if line(a, key) == line(b, key) {
			t.Errorf("two clients share %s (%q) — their traffic is correlatable", key, line(a, key))
		}
	}
	// I1 (STUN) is uniform BY DESIGN: a valid Binding Request is fixed-shape, so
	// every client sends the same canonical request (the TID is re-randomised per
	// handshake by the module). Uniqueness is carried by I2, asserted above.
	if got := line(a, "I1"); got == "" {
		t.Error("I1 (STUN) line missing from the rendered client config")
	} else if got != line(b, "I1") {
		t.Errorf("I1 (STUN) should be uniform across clients, got %q vs %q", got, line(b, "I1"))
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
		spec := clientSpec()
		local := clientDecoy(spec, domain.WGClient{PublicKey: pub})
		p := domain.AWGParams{Shared: spec.AWG.Shared, Local: local}
		if err := p.ValidateUserspace(); err != nil {
			t.Errorf("client %d decoy is not userspace-safe: %v", i, err)
		}
	}
}

const (
	testClientPubA = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	testClientPubB = "2rDXqPqGSJTGRPSaG9jZQMkNFSpsRDIWTuUvBTIBEB8="
)

// Every client's junk window must clear the shared S4, and the spread must
// survive the flooring.
//
// clientDecoy derived the local half directly and so skipped the floor
// DeriveAWGParamsForEnd applies everywhere else. The numbers made that the common
// case, not an edge one: Jmin is drawn from [8,40] and the floor is S4+8 with S4
// in [16,32], so most credentials sent junk short enough to underflow a receiver
// that strips S4 before length-checking — the failure that crash-looped mihomo on
// the master↔exit tunnel, pointed at end users' apps instead.
func TestClientDecoyClearsTheSharedS4(t *testing.T) {
	spec := clientSpec()
	floor := spec.AWG.Shared.S4 + domain.AWGJunkS4Margin
	seen := map[int]bool{}
	for i := range 200 {
		local := clientDecoy(spec, domain.WGClient{PublicKey: fmt.Sprintf("client-%d", i)})
		if local.Jmin < floor {
			t.Fatalf("client %d: Jmin %d is below S4+%d (%d)", i, local.Jmin, domain.AWGJunkS4Margin, floor)
		}
		if local.Jmin >= local.Jmax {
			t.Fatalf("client %d: flooring broke Jmin < Jmax (%d/%d)", i, local.Jmin, local.Jmax)
		}
		seen[local.Jmin] = true
	}
	// Clamping to the floor would satisfy the check above while collapsing every
	// client below it onto one value, which is the correlation the per-credential
	// decoy exists to prevent.
	if len(seen) < 10 {
		t.Errorf("only %d distinct Jmin values across 200 clients — flooring collapsed the spread", len(seen))
	}
}

// With the IPv6 block on, BOTH ends have to be addressed in the prefix: the client
// needs a v6 address or its OS installs no ::/0 route at all and the block does
// nothing, and the master needs one or it has no source address to send the ICMPv6
// rejection from — which is the entire difference between blocking IPv6 and
// black-holing it.
func TestIPv6BlockAddressesBothEnds(t *testing.T) {
	spec := clientSpec()
	prefix, err := ClientULAFor(spec.AddressPool)
	if err != nil {
		t.Fatal(err)
	}
	spec.IPv6Prefix = prefix.String()
	spec.AllowedIPs = []string{"0.0.0.0/0", "::/0"}

	// The interface the master brings up.
	iface, err := RenderClientInterface(ClientInterfaceInput{Spec: spec, PrivateKey: "c2VydmVyLXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA="})
	if err != nil {
		t.Fatalf("interface: %v", err)
	}
	gwV6, _ := ClientV6For(prefix, netip.MustParseAddr("10.80.0.1"))
	if !strings.Contains(iface, gwV6.String()+"/64") {
		t.Errorf("the master's interface has no address in %v; it cannot answer IPv6:\n%s", prefix, iface)
	}
	// Every peer must be reachable in v6 too, or the rejection cannot be routed back.
	peerV6, _ := ClientV6For(prefix, netip.MustParseAddr("10.80.0.2"))
	if !strings.Contains(iface, peerV6.String()+"/128") {
		t.Errorf("peer 10.80.0.2 has no v6 AllowedIPs entry:\n%s", iface)
	}

	// The config the client imports.
	cfg, err := RenderClientConfig(ClientConfigInput{
		Spec: spec,
		Client: domain.WGClient{Name: "laptop", Address: "10.80.0.2/32", PublicKey: testClientPubA,
			PrivateKey: "Y2xpZW50LXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA=", PresharedKey: "cHNrLWxhcHRvcC0wMDAwMDAwMDAwMDAwMDAwMDAwMA="},
		ServerPublicKey: "c2VydmVyLXB1YmxpYy0wMDAwMDAwMDAwMDAwMDAwMDA=", Endpoint: "203.0.113.1:443",
	})
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if !strings.Contains(cfg, peerV6.String()+"/128") {
		t.Errorf("the client config carries no v6 address, so the OS installs no ::/0 route:\n%s", cfg)
	}
	if !strings.Contains(cfg, "::/0") {
		t.Errorf("the client config carries no ::/0:\n%s", cfg)
	}
}

// And with no prefix nothing about v6 appears — the default every fleet runs.
func TestNoIPv6WithoutAPrefix(t *testing.T) {
	spec := clientSpec()
	iface, err := RenderClientInterface(ClientInterfaceInput{Spec: spec, PrivateKey: "c2VydmVyLXByaXZhdGUtMDAwMDAwMDAwMDAwMDAwMA="})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(iface, "fd") && strings.Contains(iface, "::") {
		t.Errorf("v6 leaked into the default interface render:\n%s", iface)
	}
}
