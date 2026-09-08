package keybroker

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// masterPSK is a valid 32-byte base64 key, the shape a real preshared key has.
// The lifeline derives its own per-exit PSK from it, so the test needs one that
// actually decodes.
const masterPSK = "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc="

// lifelineFleet is the smallest manifest that renders a lifeline: one managed
// master with a client pool, one exit carrying the reserve interface. Names are
// deliberately short and pools are documentation ranges — nothing here points at
// the live fleet.
func lifelineFleet() config.FleetSection {
	managed := true
	return config.FleetSection{
		Masters: []config.MasterConfig{{
			Name:     "m",
			MgmtAddr: "10.20.25.254",
			ClientAWG: config.ClientAWGConfig{
				ListenPort:  443,
				AddressPool: "10.80.0.0/24",
				Managed:     &managed,
				Keepalive:   "15-25",
				AllowedIPs:  []string{"0.0.0.0/0"},
			},
			Routing: config.MasterRouting{DirectCIDRs: []string{"10.0.0.0/8"}, Balance: "health"},
		}},
		Exits: []config.ExitConfig{{
			Name:        "e",
			Region:      "de",
			Egress:      "direct",
			AddressPool: "10.81.0.0/24",
			DNSFilter:   true,
			Lifeline: &config.LifelineConfig{
				ListenPort:  41827,
				AddressPool: "10.98.77.0/24",
			},
		}},
	}
}

// brokerWithLifeline seeds both node records, stamps the exit's wire version at
// the one that understands the lifeline block, and issues two credentials on the
// master: an enabled one at .5 (with a preshared key) and a muted one at .6.
func brokerWithLifeline(t *testing.T, fleet config.FleetSection) (*Broker, store.Store, context.Context) {
	t.Helper()
	b, st := newBrokerWithFleet(t, fleet)
	ctx := context.Background()
	seedNode(t, st, "m", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	seedNode(t, st, "e", "10.20.0.5", "198.51.100.7",
		"A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=", domain.RoleExit)
	setWireVersion(t, st, "m", api.WireLifeline)
	setWireVersion(t, st, "e", api.WireLifeline)

	add := func(c domain.WGClient) {
		t.Helper()
		c.CreatedAt = time.Now()
		if err := st.AddWGClient(ctx, "m", c); err != nil {
			t.Fatalf("seed credential %q: %v", c.Name, err)
		}
	}
	add(domain.WGClient{
		ID: "c1", Name: "laptop", Address: "10.80.0.5/32",
		PublicKey:    "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY=",
		PresharedKey: masterPSK, Enabled: true,
	})
	add(domain.WGClient{
		ID: "c2", Name: "phone", Address: "10.80.0.6/32",
		PublicKey: "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=",
		Enabled:   false,
	})
	return b, st, ctx
}

func renderExit(t *testing.T, b *Broker, ctx context.Context) domain.NodeSpec {
	t.Helper()
	spec, err := b.RenderNodeSpec(ctx, "e")
	if err != nil {
		t.Fatalf("render exit: %v", err)
	}
	return spec
}

// renderLifeline is renderExit for the tests that only look at the reserve
// interface, and it fails loudly rather than letting a nil block panic.
func renderLifeline(t *testing.T, b *Broker, ctx context.Context) *domain.LifelineSpec {
	t.Helper()
	spec := renderExit(t, b, ctx)
	if spec.Lifeline == nil {
		t.Fatal("exit with a lifeline section rendered no lifeline spec")
	}
	return spec.Lifeline
}

// The whole point of the feature in one assertion: the exit carries the master's
// client population on its own pool, on its own port, behind its own firewall
// hole. A muted credential stays muted — the reserve path is a second door for
// the same people, not an amnesty.
func TestLifelineSpecProjectsTheMastersClients(t *testing.T) {
	b, _, ctx := brokerWithLifeline(t, lifelineFleet())
	spec := renderExit(t, b, ctx)

	if spec.Lifeline == nil {
		t.Fatal("exit with a lifeline section rendered no lifeline spec")
	}
	l := spec.Lifeline
	if l.ListenPort != 41827 {
		t.Errorf("ListenPort = %d, want 41827", l.ListenPort)
	}
	if l.AddressPool != "10.98.77.0/24" {
		t.Errorf("AddressPool = %q, want 10.98.77.0/24", l.AddressPool)
	}
	if l.ServerAddress != "10.98.77.1" {
		t.Errorf("ServerAddress = %q, want 10.98.77.1", l.ServerAddress)
	}
	if l.Backend != domain.ClientWGBackendKernel {
		t.Errorf("Backend = %q, want kernel", l.Backend)
	}
	if l.Keepalive != "15-25" {
		t.Errorf("Keepalive = %q, want the master's 15-25", l.Keepalive)
	}
	if !slices.Equal(l.AllowedIPs, []string{"0.0.0.0/0"}) {
		t.Errorf("AllowedIPs = %v, want the master's", l.AllowedIPs)
	}
	if len(l.Clients) != 1 {
		t.Fatalf("Clients = %+v, want exactly the enabled credential", l.Clients)
	}
	peer := l.Clients[0]
	if peer.Address != "10.98.77.5/32" {
		t.Errorf("peer address = %q, want the host offset shifted into the lifeline pool as a single host", peer.Address)
	}
	want, err := domain.LifelinePSK(masterPSK, "e")
	if err != nil {
		t.Fatal(err)
	}
	if peer.PresharedKey == masterPSK {
		t.Error("the lifeline peer reuses the master's preshared key verbatim")
	}
	if peer.PresharedKey != want {
		t.Errorf("peer PSK = %q, want the per-exit derivation %q", peer.PresharedKey, want)
	}
	if spec.Firewall.LifelinePort != 41827 {
		t.Errorf("Firewall.LifelinePort = %d, want the lifeline listener open", spec.Firewall.LifelinePort)
	}
	// The rendered block must satisfy the validation it inherits from ClientWGSpec
	// through the embedding — the agent runs it before touching the interface, so a
	// controller that renders something Validate() refuses ships a lifeline that
	// never comes up. It is also what catches a peer mask wider than a single host.
	if err := l.Validate(); err != nil {
		t.Errorf("rendered lifeline does not validate: %v", err)
	}
}

// No lifeline section is the pre-feature state: nothing rendered, no port opened.
func TestLifelineAbsentWithoutTheManifestSection(t *testing.T) {
	fleet := lifelineFleet()
	fleet.Exits[0].Lifeline = nil
	b, _, ctx := brokerWithLifeline(t, fleet)
	spec := renderExit(t, b, ctx)

	if spec.Lifeline != nil {
		t.Errorf("an exit with no lifeline section got one anyway: %+v", spec.Lifeline)
	}
	if spec.Firewall.LifelinePort != 0 {
		t.Errorf("Firewall.LifelinePort = %d, want 0", spec.Firewall.LifelinePort)
	}
}

// An agent below wire v11 drops the block, so opening the port for a listener
// that will never exist would be a hole with nothing behind it. Rendering
// neither half is the fail-safe, and it is a DECISION (the operator sees the
// warning), never a swallowed failure.
func TestLifelineNotRenderedForAnOldAgent(t *testing.T) {
	b, st, ctx := brokerWithLifeline(t, lifelineFleet())
	setWireVersion(t, st, "e", api.WireLifeline-1)
	spec := renderExit(t, b, ctx)

	if spec.Lifeline != nil {
		t.Errorf("a pre-v11 agent was handed a lifeline block: %+v", spec.Lifeline)
	}
	if spec.Firewall.LifelinePort != 0 {
		t.Errorf("Firewall.LifelinePort = %d, want the hole closed too", spec.Firewall.LifelinePort)
	}
}

// Same rule as the master's client interface: a transient store failure must not
// render a lifeline with no peers. That spec is structurally valid, so nothing
// downstream would reject it, and the agent would apply it and lock every user
// out of the reserve path exactly when they need it.
func TestLifelineSpecFailsRatherThanEmptyingTheInterface(t *testing.T) {
	b, st, ctx := brokerWithLifeline(t, lifelineFleet())
	if spec := renderExit(t, b, ctx); spec.Lifeline == nil || len(spec.Lifeline.Clients) != 1 {
		t.Fatalf("fixture is not exercising the path: %+v", spec.Lifeline)
	}

	boom := errors.New("database is locked")
	b.store = flakyClientStore{Store: st, err: boom}
	spec, err := b.RenderNodeSpec(ctx, "e")
	if err == nil {
		t.Fatalf("render succeeded despite an unreadable store; Lifeline = %+v", spec.Lifeline)
	}
	if !errors.Is(err, boom) {
		t.Errorf("render error = %v, want it to wrap the store failure", err)
	}
}

// The lifeline is its own tunnel, so it gets its own obfuscation seed — sharing
// the master↔exit tunnel's would give an observer one profile spanning two
// independent paths.
func TestLifelineAWGDerivesFromItsOwnSeed(t *testing.T) {
	b, _, ctx := brokerWithLifeline(t, lifelineFleet())
	spec := renderExit(t, b, ctx)

	if spec.Lifeline == nil || spec.Lifeline.AWG == nil {
		t.Fatalf("lifeline rendered without AmneziaWG params: %+v", spec.Lifeline)
	}
	want := wg.DeriveAWGShared(wg.TunnelSeed("e", "lifeline", awgSalt))
	if spec.Lifeline.AWG.Shared != want {
		t.Errorf("lifeline AWG shared params = %+v, want the lifeline seed's %+v", spec.Lifeline.AWG.Shared, want)
	}
	if spec.WGServer.AWG != nil && spec.Lifeline.AWG.Shared == spec.WGServer.AWG.Shared {
		t.Error("the lifeline shares the master↔exit tunnel's obfuscation profile")
	}
	if spec.Lifeline.AWG.AWG3Enabled() {
		t.Error("AWG 3.x rendered without the operator opting in")
	}
}

// The 3.x generation follows the master's client_awg.awg3 knob: the lifeline
// serves the SAME client configs as the master's interface, so a client that can
// speak 3.x there must find 3.x here, and one that cannot must find neither.
func TestLifelineAWG3FollowsTheClientKnob(t *testing.T) {
	fleet := lifelineFleet()
	fleet.Masters[0].ClientAWG.AWG3 = string(config.ClientAWG3Timers)
	b, _, ctx := brokerWithLifeline(t, fleet)
	l := renderLifeline(t, b, ctx)

	if !l.AWG.AWG3Enabled() {
		t.Fatalf("client_awg.awg3: timers did not reach the lifeline: %+v", l.AWG)
	}
	if l.AWG.Shared.HeaderProtectionKey != "" {
		t.Error("timers mode enabled header protection, which disconnects every client")
	}
}

func TestLifelineAWG3FullAddsHeaderProtection(t *testing.T) {
	fleet := lifelineFleet()
	fleet.Masters[0].ClientAWG.AWG3 = string(config.ClientAWG3Full)
	b, _, ctx := brokerWithLifeline(t, fleet)
	l := renderLifeline(t, b, ctx)

	if l.AWG.Shared.HeaderProtectionKey == "" {
		t.Errorf("client_awg.awg3: full did not enable header protection: %+v", l.AWG)
	}
}

// Without the master there is no resolver a lifeline client can reach except the
// exit's own blocky, which sits on the lifeline gateway address.
func TestLifelineDNSFallsBackToTheExitsOwnResolver(t *testing.T) {
	b, _, ctx := brokerWithLifeline(t, lifelineFleet())
	l := renderLifeline(t, b, ctx)

	if !slices.Equal(l.DNS, []string{"10.98.77.1"}) {
		t.Errorf("DNS = %v, want the lifeline gateway (dns_filter is on)", l.DNS)
	}
}

func TestLifelineDNSFromTheManifestWins(t *testing.T) {
	fleet := lifelineFleet()
	fleet.Exits[0].Lifeline.DNS = []string{"10.98.77.53"}
	b, _, ctx := brokerWithLifeline(t, fleet)
	l := renderLifeline(t, b, ctx)

	if !slices.Equal(l.DNS, []string{"10.98.77.53"}) {
		t.Errorf("DNS = %v, want the manifest's", l.DNS)
	}
}

func TestLifelineEgressMirrorsTheManifest(t *testing.T) {
	b, _, ctx := brokerWithLifeline(t, lifelineFleet())
	if got := renderLifeline(t, b, ctx).Egress; got != domain.EgressDirect {
		t.Errorf("egress = %q, want direct by default", got)
	}

	fleet := lifelineFleet()
	fleet.Exits[0].Egress = "warp"
	fleet.Exits[0].Lifeline.Egress = "warp"
	b, _, ctx = brokerWithLifeline(t, fleet)
	if got := renderLifeline(t, b, ctx).Egress; got != domain.EgressWARP {
		t.Errorf("egress = %q, want warp", got)
	}
}

// MTU is computed, not guessed, and the expected values are written
// out as literals rather than recomputed from the same helpers the implementation
// uses — a test that repeats the formula cannot catch the formula being wrong.
//
// The WARP row is the one that matters: awgl0 and wgcf are TERMINATING hops, so
// the client payload must fit each of them independently. Subtracting an AWG
// layer from the wgcf MTU as well would put this at 1240 (below wg.MinTunnelMTU)
// and charge the same overhead twice.
func TestLifelineMTU(t *testing.T) {
	direct := lifelineFleet()

	warp := lifelineFleet()
	warp.Exits[0].Egress = "warp"
	warp.Exits[0].Lifeline.Egress = "warp"

	narrowWARP := lifelineFleet()
	narrowWARP.Exits[0].Egress = "warp"
	narrowWARP.Exits[0].Lifeline.Egress = "warp"
	narrowWARP.Exits[0].WARPMTU = 1320

	narrowLink := lifelineFleet()
	narrowLink.Exits[0].LinkMTU = 1400

	pinned := lifelineFleet()
	pinned.Exits[0].Lifeline.MTU = 1300

	cases := []struct {
		name  string
		fleet config.FleetSection
		want  int
		why   string
	}{
		{"direct", direct, 1360, "1500 link minus one AWG layer (60 + 80)"},
		{"warp", warp, 1360, "min(1360 tunnel, the wgcf MTU as is) — the AWG layer is NOT charged twice"},
		{"warp_pinned_narrow", narrowWARP, 1320, "the wgcf leg is now the narrower hop"},
		{"narrow_link", narrowLink, 1260, "1400 link minus one AWG layer"},
		{"operator_override", pinned, 1300, "lifeline.mtu wins outright"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, ctx := brokerWithLifeline(t, tc.fleet)
			if got := renderLifeline(t, b, ctx).MTU; got != tc.want {
				t.Errorf("MTU = %d, want %d (%s)", got, tc.want, tc.why)
			}
		})
	}
}

// A credential outside the master's pool cannot be projected onto the lifeline,
// and guessing is worse than failing: the render fails and the exit keeps its
// last-good interface.
func TestLifelineSpecFailsOnAnUnprojectableCredential(t *testing.T) {
	b, st, ctx := brokerWithLifeline(t, lifelineFleet())
	if err := st.AddWGClient(ctx, "m", domain.WGClient{
		ID: "c3", Name: "stray", Address: "192.0.2.9/32",
		PublicKey: "cJ0Fp0J8sQCC0mF2iM6JEcbRlm2YM7WdM3ETHTMwQXA=", Enabled: true,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed stray credential: %v", err)
	}
	if _, err := b.RenderNodeSpec(ctx, "e"); err == nil {
		t.Fatal("a credential outside the master pool rendered a lifeline instead of failing")
	}
}
