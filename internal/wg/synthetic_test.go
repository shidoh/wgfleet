package wg

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func synthSpec() domain.ClientWGSpec {
	return domain.ClientWGSpec{
		ListenPort: 443, AddressPool: "10.73.0.0/24", ServerAddress: "10.73.0.1", MTU: 1360,
		Clients: []domain.WGClientPeer{{Name: "laptop", PublicKey: "AAAA", Address: "10.73.0.2/32"}},
	}
}

// The prober must appear on the interface as an ordinary peer. A prober that
// takes a shortcut measures the shortcut: it has to handshake with the same
// obfuscation and traverse the same chains as a real client, or it proves nothing
// about the path real clients take.
func TestWithSyntheticPeerAddsAnOrdinaryPeer(t *testing.T) {
	peer := SyntheticClient("10.73.0.254/32", "priv", "BBBB")
	spec := WithSyntheticPeer(synthSpec(), peer)

	if len(spec.Clients) != 2 {
		t.Fatalf("peer count = %d, want the end user plus the prober", len(spec.Clients))
	}
	conf, err := RenderClientInterface(ClientInterfaceInput{Spec: spec, PrivateKey: "serverkey"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(conf, "10.73.0.254/32") || !strings.Contains(conf, "BBBB") {
		t.Errorf("the prober is not on the interface:\n%s", conf)
	}
	if !strings.Contains(conf, SyntheticPeerName) {
		t.Errorf("the prober is not named, so it reads as an unexplained extra peer:\n%s", conf)
	}
}

// Applied twice it must change nothing: this runs on every reconcile pass, and a
// peer list that grows once a minute would rewrite the interface config forever.
func TestWithSyntheticPeerIsIdempotent(t *testing.T) {
	peer := SyntheticClient("10.73.0.254/32", "priv", "BBBB")
	once := WithSyntheticPeer(synthSpec(), peer)
	twice := WithSyntheticPeer(once, peer)
	if len(twice.Clients) != len(once.Clients) {
		t.Errorf("peer count grew from %d to %d on re-application", len(once.Clients), len(twice.Clients))
	}
}

// Without a key there is nothing to add, and adding a peer with an empty public
// key would make awg-quick refuse the whole interface — taking the client leg
// down to measure it.
func TestWithSyntheticPeerIsInertWithoutAKey(t *testing.T) {
	spec := WithSyntheticPeer(synthSpec(), SyntheticClient("10.73.0.254/32", "", ""))
	if len(spec.Clients) != 1 {
		t.Errorf("a keyless prober was added anyway: %+v", spec.Clients)
	}
}

// The prober's own config must be renderable from the same renderer end users
// get — same obfuscation, same MTU. A separate renderer would drift.
func TestSyntheticClientConfigUsesTheClientRenderer(t *testing.T) {
	peer := SyntheticClient("10.73.0.254/32", "privkey", "BBBB")
	conf, err := RenderClientConfig(ClientConfigInput{
		Spec: synthSpec(), Client: peer, ServerPublicKey: "SRV", Endpoint: "100.127.255.5:443",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"PrivateKey = privkey", "10.73.0.254/32", "SRV", "100.127.255.5:443"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in the prober's config:\n%s", want, conf)
		}
	}
}

// setconf understands the device and rejects what awg-quick owns. Getting this
// wrong means the prober's interface never comes up and the path goes unmeasured
// while everything reports fine — the failure mode this whole feature exists to
// end, reproduced in the thing that watches for it.
func TestSyntheticSetConfIsDeviceOnlyAndCarriesTheObfuscation(t *testing.T) {
	spec := synthSpec()
	spec.AWG = &domain.AWGParams{
		Shared: domain.AWGShared{
			S1: 39, S2: 61,
			H1: domain.AWGHeader{Min: 1, Max: 2}, H2: domain.AWGHeader{Min: 3, Max: 4},
			H3: domain.AWGHeader{Min: 5, Max: 6}, H4: domain.AWGHeader{Min: 7, Max: 8},
		},
	}
	out, err := RenderSyntheticSetConf(SyntheticSetConfInput{
		Spec:            spec,
		Client:          SyntheticClient("10.73.0.254/32", "privkey", "PUB"),
		ServerPublicKey: "SRV",
		Endpoint:        "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"PrivateKey = privkey", "PublicKey = SRV", "Endpoint = 127.0.0.1:443", "S1 = 39", "H1 = "} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// awg-quick's own directives must NOT be here: setconf rejects the file if they are.
	for _, forbidden := range []string{"Address =", "DNS =", "MTU ="} {
		if strings.Contains(out, forbidden) {
			t.Errorf("setconf form carries %q, which awg setconf rejects:\n%s", forbidden, out)
		}
	}
}
