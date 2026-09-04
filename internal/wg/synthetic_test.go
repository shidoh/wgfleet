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
