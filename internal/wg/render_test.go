package wg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestGenerateAndDeriveKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidKey(kp.PrivateKey) || !ValidKey(kp.PublicKey) {
		t.Fatalf("generated keys invalid: %+v", kp)
	}
	pub, err := PublicKeyOf(kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.PublicKey {
		t.Errorf("derived pub %q != %q", pub, kp.PublicKey)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg", "private.key")

	kp1, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("first call should create the key")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key perm = %o, want 600", info.Mode().Perm())
	}

	kp2, created, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Error("second call should load, not create")
	}
	if kp1.PrivateKey != kp2.PrivateKey {
		t.Error("key changed between load calls")
	}
}

func TestRenderExitInterfaceNoEndpointForDialingPeer(t *testing.T) {
	// Exit is the server; the master dials in, so the master peer must have NO
	// Endpoint line (a bogus endpoint breaks the tunnel).
	cfg, err := RenderInterface(RenderInput{
		Spec: domain.WGServerSpec{
			ListenPort:  51820,
			AddressPool: "10.81.0.0/24",
			Address:     "10.81.0.1",
			MTU:         1440,
		},
		Peers: []domain.PeerSpec{{
			Name:       "master-xa-1",
			PublicKey:  testPubKey(t),
			AllowedIPs: []string{"10.81.0.2/32"},
			Keepalive:  25,
			// Endpoint intentionally empty
		}},
		PrivateKey: testPrivKey(t),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(cfg, "Address = 10.81.0.1/24") {
		t.Errorf("missing/incorrect Address line:\n%s", cfg)
	}
	if !strings.Contains(cfg, "ListenPort = 51820") || !strings.Contains(cfg, "MTU = 1440") {
		t.Errorf("missing listen/mtu:\n%s", cfg)
	}
	if strings.Contains(cfg, "Endpoint =") {
		t.Errorf("dialing peer must not have an Endpoint:\n%s", cfg)
	}
	if !strings.Contains(cfg, "PersistentKeepalive = 25") {
		t.Errorf("missing keepalive:\n%s", cfg)
	}
}

func TestRenderMasterPeerHasEndpoint(t *testing.T) {
	cfg, err := RenderInterface(RenderInput{
		Spec: domain.WGServerSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"},
		Peers: []domain.PeerSpec{{
			Name:       "exit-de-1",
			PublicKey:  testPubKey(t),
			Endpoint:   "198.51.100.7:51820",
			AllowedIPs: []string{"10.81.0.1/32"},
		}},
		PrivateKey: testPrivKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "Endpoint = 198.51.100.7:51820") {
		t.Errorf("master must dial exit via Endpoint:\n%s", cfg)
	}
	// Address defaults to first host of pool when unset.
	if !strings.Contains(cfg, "Address = 10.80.0.1/24") {
		t.Errorf("default address not derived:\n%s", cfg)
	}
}

func TestRenderAWGInterfaceParams(t *testing.T) {
	cfg, err := RenderInterface(RenderInput{
		Spec: domain.WGServerSpec{
			ListenPort:  51820,
			AddressPool: "10.81.0.0/24",
			Address:     "10.81.0.1",
			AWG: &domain.AWGParams{
				Shared: domain.AWGShared{
					H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
					H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
					H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
					H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
					S1: 102, S2: 67,
				},
				Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900, I1: "<b 0xdeadbeef>"},
			},
		},
		Peers:      []domain.PeerSpec{{Name: "m", PublicKey: testPubKey(t), AllowedIPs: []string{"10.81.0.2/32"}}},
		PrivateKey: testPrivKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	// H ranges render as min-max; local junk + signature packets present.
	for _, want := range []string{
		"H1 = 15384729-145384729", "H4 = 1524719384-1654719384",
		"S1 = 102", "S2 = 67", "Jc = 5", "Jmax = 900", "I1 = <b 0xdeadbeef>",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("AWG config missing %q:\n%s", want, cfg)
		}
	}
	// All AWG params must be in [Interface], before the first [Peer].
	ifaceSection := cfg[:strings.Index(cfg, "[Peer]")]
	for _, want := range []string{"Jc =", "S1 =", "H1 =", "I1 ="} {
		if !strings.Contains(ifaceSection, want) {
			t.Errorf("AWG param %q must be in [Interface] section", want)
		}
	}
}

func TestRenderRejectsInvalidAWG(t *testing.T) {
	_, err := RenderInterface(RenderInput{
		Spec: domain.WGServerSpec{
			AddressPool: "10.81.0.0/24",
			Address:     "10.81.0.1",
			AWG: &domain.AWGParams{
				Shared: domain.AWGShared{
					H1: domain.AWGHeader{Min: 100, Max: 200},
					H2: domain.AWGHeader{Min: 150, Max: 250}, // overlaps H1
					H3: domain.AWGHeader{Min: 300, Max: 400},
					H4: domain.AWGHeader{Min: 500, Max: 600},
				},
				Local: domain.AWGLocal{Jc: 8, Jmin: 8, Jmax: 80},
			},
		},
		Peers:      []domain.PeerSpec{{Name: "m", PublicKey: testPubKey(t), AllowedIPs: []string{"10.81.0.2/32"}}},
		PrivateKey: testPrivKey(t),
	})
	if err == nil {
		t.Fatal("expected error for overlapping AWG header ranges")
	}
}

func TestRedactConfigMasksPrivateKey(t *testing.T) {
	cfg, _ := RenderInterface(RenderInput{
		Spec:       domain.WGServerSpec{AddressPool: "10.81.0.0/24", Address: "10.81.0.1"},
		Peers:      []domain.PeerSpec{{Name: "m", PublicKey: testPubKey(t), AllowedIPs: []string{"10.81.0.2/32"}}},
		PrivateKey: testPrivKey(t),
	})
	red := RedactConfig(cfg)
	if strings.Contains(red, testPrivKey(t)) {
		t.Errorf("redaction leaked private key:\n%s", red)
	}
	if !strings.Contains(red, "PrivateKey = <redacted>") {
		t.Errorf("redaction marker missing:\n%s", red)
	}
}

func TestRenderRequiresPrivateKey(t *testing.T) {
	_, err := RenderInterface(RenderInput{
		Spec: domain.WGServerSpec{AddressPool: "10.81.0.0/24", Address: "10.81.0.1"},
	})
	if err == nil {
		t.Fatal("expected error without private key")
	}
}

// --- shared test keys (deterministic per run) ---

var cachedPriv, cachedPub string

func testPrivKey(t *testing.T) string {
	t.Helper()
	if cachedPriv == "" {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		cachedPriv, cachedPub = kp.PrivateKey, kp.PublicKey
	}
	return cachedPriv
}

func testPubKey(t *testing.T) string {
	t.Helper()
	testPrivKey(t)
	return cachedPub
}
