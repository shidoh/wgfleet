package keybroker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// managedFleet returns the test fleet with the master's client interface handed
// to the agent.
func managedFleet() config.FleetSection {
	f := testFleet()
	managed := true
	f.Masters[0].ClientAWG.Managed = &managed
	return f
}

func brokerWithManagedMaster(t *testing.T) (*Broker, store.Store, context.Context) {
	t.Helper()
	b, st := newBrokerWithFleet(t, managedFleet())
	ctx := context.Background()
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	// The client leg is gated on the agent being able to take it (wire v8), so the
	// fixture must report a version like a real registered master does.
	setWireVersion(t, st, "master-xa-1", api.WireClientWG)
	return b, st, ctx
}

// setWireVersion stamps the wire contract a registered agent reports.
func setWireVersion(t *testing.T, st store.Store, id string, version uint32) {
	t.Helper()
	ctx := context.Background()
	node, err := st.GetNode(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	node.WireVersion = version
	if err := st.UpsertNode(ctx, node); err != nil {
		t.Fatal(err)
	}
}

func TestIssueWGClientMintsKeysAndAddress(t *testing.T) {
	b, st, ctx := brokerWithManagedMaster(t)

	first, err := b.IssueWGClient(ctx, "master-xa-1", "laptop")
	if err != nil {
		t.Fatalf("issue laptop: %v", err)
	}
	second, err := b.IssueWGClient(ctx, "master-xa-1", "phone")
	if err != nil {
		t.Fatalf("issue phone: %v", err)
	}

	if first.PrivateKey == "" || first.PublicKey == "" {
		t.Fatal("issued credential has no keypair")
	}
	if first.PrivateKey == second.PrivateKey || first.PublicKey == second.PublicKey {
		t.Fatal("two credentials share a keypair")
	}
	if first.ID == second.ID {
		t.Fatal("two credentials share an ID")
	}
	// The pool is 10.80.0.0/24 and .1 is the master itself.
	if first.Address != "10.80.0.2/32" || second.Address != "10.80.0.3/32" {
		t.Fatalf("addresses = %q, %q; want 10.80.0.2/32, 10.80.0.3/32", first.Address, second.Address)
	}
	if !first.Enabled {
		t.Error("a freshly issued credential should be enabled")
	}
	if first.CreatedAt.IsZero() {
		t.Error("CreatedAt not stamped")
	}

	stored, err := st.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("store holds %d credentials, want 2", len(stored))
	}
}

// Issuance is a mint followed by a plain write: the keypair and the address are
// decided BEFORE the store call, so replaying that write on another replica
// cannot produce a different result (ADR-0027's FSM).
func TestIssueWGClientAddressSurvivesRevocation(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	for _, name := range []string{"a", "b", "c"} {
		if _, err := b.IssueWGClient(ctx, "master-xa-1", name); err != nil {
			t.Fatalf("issue %s: %v", name, err)
		}
	}
	// Free the middle address, then issue again: the hole is reused.
	clients, err := b.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var bID string
	for _, c := range clients {
		if c.Name == "b" {
			bID = c.ID
		}
	}
	if err := b.RevokeWGClient(ctx, "master-xa-1", bID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	next, err := b.IssueWGClient(ctx, "master-xa-1", "d")
	if err != nil {
		t.Fatalf("issue d: %v", err)
	}
	if next.Address != "10.80.0.3/32" {
		t.Fatalf("address = %q, want the freed 10.80.0.3/32", next.Address)
	}
}

func TestIssueWGClientRejectsBadInput(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	if _, err := b.IssueWGClient(ctx, "master-xa-1", ""); err == nil {
		t.Error("issuing an unnamed credential should fail")
	}
	if _, err := b.IssueWGClient(ctx, "master-xa-1", "laptop"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := b.IssueWGClient(ctx, "master-xa-1", "laptop"); err == nil {
		t.Error("re-issuing an existing name should fail rather than replace the credential")
	}
	if _, err := b.IssueWGClient(ctx, "nope", "laptop"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("issuing for an unknown master = %v, want ErrNotFound", err)
	}
}

// A master whose pool has no room left must fail loudly rather than hand out a
// duplicate address.
func TestIssueWGClientPoolExhausted(t *testing.T) {
	fleet := managedFleet()
	fleet.Masters[0].ClientAWG.AddressPool = "10.80.0.0/29" // .2-.6 usable
	b, st := newBrokerWithFleet(t, fleet)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	setWireVersion(t, st, "master-xa-1", api.WireClientWG)
	ctx := context.Background()

	// FOUR, not five. The pool has five usable addresses (.2-.6) and the top one is
	// held for the master's synthetic client, which measures whether a packet
	// entering the client interface comes back — the one fact every component
	// metric missed while client QUIC was dead for eight days. Reserving it costs
	// exactly one client address, and that cost belongs in a test rather than in a
	// surprise on a full pool.
	var issued []string
	for i := range 4 {
		c, err := b.IssueWGClient(ctx, "master-xa-1", string(rune('a'+i)))
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		issued = append(issued, c.Address)
	}
	_, err := b.IssueWGClient(ctx, "master-xa-1", "overflow")
	if !errors.Is(err, domain.ErrPoolExhausted) {
		t.Fatalf("issue into a full pool = %v, want ErrPoolExhausted", err)
	}

	synth, err := domain.SyntheticClientAddress("10.80.0.0/29")
	if err != nil {
		t.Fatalf("SyntheticClientAddress: %v", err)
	}
	for _, a := range issued {
		if a == synth {
			t.Errorf("a real client was issued the synthetic address %s", synth)
		}
	}
}

func TestRenderMasterSpecCarriesClientWG(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	if _, err := b.IssueWGClient(ctx, "master-xa-1", "laptop"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	phone, err := b.IssueWGClient(ctx, "master-xa-1", "phone")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := b.SetWGClientEnabled(ctx, "master-xa-1", phone.ID, false); err != nil {
		t.Fatalf("mute: %v", err)
	}

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cw := spec.Master.ClientWG
	if cw == nil {
		t.Fatal("managed master rendered without a client WG spec")
	}
	if err := cw.Validate(); err != nil {
		t.Fatalf("rendered client WG spec is invalid: %v", err)
	}
	if cw.ListenPort != 443 || cw.AddressPool != "10.80.0.0/24" || cw.ServerAddress != "10.80.0.1" {
		t.Errorf("interface = port %d, pool %q, address %q", cw.ListenPort, cw.AddressPool, cw.ServerAddress)
	}
	if cw.MTU != spec.WGServer.MTU {
		t.Errorf("client interface MTU = %d, want the derived %d", cw.MTU, spec.WGServer.MTU)
	}
	if cw.AWG == nil {
		t.Fatal("client interface must carry the AWG profile")
	}
	// The obfuscation must be the SAME derivation the client-facing WGServer uses:
	// clients configured before the handover keep working.
	if cw.AWG.Shared != spec.WGServer.AWG.Shared {
		t.Error("client interface shared AWG params differ from the client-facing server's")
	}
	// Only the enabled credential is a peer, and no private key travels.
	if len(cw.Clients) != 1 || cw.Clients[0].Name != "laptop" {
		t.Fatalf("peers = %+v, want only the enabled laptop", cw.Clients)
	}
	if cw.Clients[0].PublicKey == "" {
		t.Error("peer has no public key")
	}
}

func TestRenderMasterSpecOmitsClientWGWhenUnmanaged(t *testing.T) {
	ctx := context.Background()
	b, st := newBroker(t) // testFleet(): managed unset ⇒ wg-easy still owns the leg
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	if _, err := b.IssueWGClient(ctx, "master-xa-1", "laptop"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master.ClientWG != nil {
		t.Fatal("an unmanaged master must not render a client WG spec, even with credentials issued")
	}
}

// Renaming keeps identity, keys and address; that is the whole point of having an
// ID separate from the label.
func TestRenameWGClientKeepsIdentity(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	c, err := b.IssueWGClient(ctx, "master-xa-1", "laptop")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := b.RenameWGClient(ctx, "master-xa-1", c.ID, "work-laptop"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	clients, err := b.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("list returned %d, want 1", len(clients))
	}
	got := clients[0]
	if got.Name != "work-laptop" || got.ID != c.ID || got.PublicKey != c.PublicKey || got.Address != c.Address {
		t.Fatalf("rename altered the credential: %+v", got)
	}
}

func TestIssueWGClientNameValidation(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	_, err := b.IssueWGClient(ctx, "master-xa-1", strings.Repeat("x", 65))
	if err == nil {
		t.Error("an over-long name should be rejected")
	}
}

// --- the wire gate -------------------------------------------------------
//
// The knob alone is not enough. A v7 agent drops MasterSpec.client_wg and keeps
// wg-easy serving the client leg, while the controller has already stopped
// reconciling wg-easy's database and treats its own store as the truth. Two
// owners of the one interface end users dial, and neither side errors.

func TestClientWGSpecRefusedForATooOldAgent(t *testing.T) {
	b, st := newBrokerWithFleet(t, managedFleet())
	ctx := context.Background()
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)

	// A master that has registered but reports an older wire contract.
	setWireVersion(t, st, "master-xa-1", api.WireClientWG-1)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master.ClientWG != nil {
		t.Fatal("controller handed the client leg to an agent that cannot take it")
	}
}

func TestClientWGSpecRenderedForACurrentAgent(t *testing.T) {
	b, st := newBrokerWithFleet(t, managedFleet())
	ctx := context.Background()
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	setWireVersion(t, st, "master-xa-1", api.WireClientWG)

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master.ClientWG == nil {
		t.Fatal("a current agent was refused the client interface")
	}
}

// managedFleetAWG3 is a handed-over master whose CLIENT leg opts into a 3.x mode.
func managedFleetAWG3(mode config.ClientAWG3Mode) config.FleetSection {
	f := managedFleet()
	f.Masters[0].ClientAWG.AWG3 = string(mode)
	return f
}

// renderedClientAWG renders the master spec and returns the client leg's params.
func renderedClientAWG(t *testing.T, f config.FleetSection) (client domain.AWGParams, wgEasy domain.AWGParams) {
	t.Helper()
	b, st := newBrokerWithFleet(t, f)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	setWireVersion(t, st, "master-xa-1", api.WireClientWG)
	spec, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master.ClientWG == nil || spec.Master.ClientWG.AWG == nil {
		t.Fatal("no client interface params rendered")
	}
	if spec.WGServer.AWG == nil {
		t.Fatal("no wg-easy params rendered")
	}
	return *spec.Master.ClientWG.AWG, *spec.WGServer.AWG
}

// The default is AmneziaWG 2.0. An operator who never touched the knob must not
// find header protection on the leg their users dial.
func TestClientLegDefaultsToAWG2(t *testing.T) {
	got, _ := renderedClientAWG(t, managedFleet())
	if got.AWG3Enabled() {
		t.Fatalf("client leg opted itself into 3.x: %+v", got.Shared)
	}
}

// "timers" is the mode that costs nothing: the client leg randomises its timers
// and every config already in a user's hands keeps working, which was measured
// against a real 3.1 module. The absence of a header-protection key is what makes
// that true, so it is what this asserts.
func TestClientLegTimersModeKeepsOldConfigsWorking(t *testing.T) {
	got, _ := renderedClientAWG(t, managedFleetAWG3(config.ClientAWG3Timers))
	if got.Shared.HeaderProtectionKey != "" {
		t.Fatal("timers mode set a header-protection key, which disconnects every existing client")
	}
	if got.Shared.RekeyAfterTime == "" || got.Shared.KeepaliveTimeout == "" {
		t.Fatalf("timers mode left the timers unset: %+v", got.Shared)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("timers mode produced invalid params: %v", err)
	}
}

// "full" is the flag day: header protection on top of the timers.
func TestClientLegFullModeAddsHeaderProtection(t *testing.T) {
	got, _ := renderedClientAWG(t, managedFleetAWG3(config.ClientAWG3Full))
	if got.Shared.HeaderProtectionKey == "" {
		t.Fatal("full mode set no header-protection key")
	}
	if got.Shared.RekeyAfterTime == "" {
		t.Fatal("full mode dropped the timers")
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("full mode produced invalid params: %v", err)
	}
}

// WGServerSpec.AWG is consumed on the master by the wg-easy planners alone, and
// wg-easy has no columns for any 3.0 parameter. Leaking the client leg's 3.x
// params into that struct would have the planner write a partial set into
// wg-easy's database on every pass — so the two must stay separate even when the
// client leg is fully on 3.x.
func TestClientLegAWG3DoesNotReachWGEasyParams(t *testing.T) {
	client, wgEasy := renderedClientAWG(t, managedFleetAWG3(config.ClientAWG3Full))
	if !client.AWG3Enabled() {
		t.Fatal("precondition: the client leg was meant to be on 3.x")
	}
	if wgEasy.AWG3Enabled() {
		t.Fatalf("3.x parameters reached the wg-easy params struct: %+v", wgEasy.Shared)
	}
}

// Both ends of the client tunnel derive from the same seed, so the server
// interface and the config a user imports must carry byte-identical shared
// params — that is what a handshake requires.
func TestClientLegAWG3IsSharedWithTheClientConfig(t *testing.T) {
	b, st := newBrokerWithFleet(t, managedFleetAWG3(config.ClientAWG3Full))
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	setWireVersion(t, st, "master-xa-1", api.WireClientWG)
	spec, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cw := spec.Master.ClientWG
	// The local half is DERIVED per credential at render time, not carried on the
	// spec, so what the interface publishes is the shared half — and that is the
	// half a client config must match byte for byte.
	if cw.AWG == nil {
		t.Fatal("the client interface lost its AWG profile")
	}
	if cw.AWG.Shared.HeaderProtectionKey == "" {
		t.Fatal("the client config would carry no header-protection key")
	}
}

// The knob is resolved in the controller and travels on the spec, because the
// config builder the UI and the portal share sees only the spec — it has no
// access to the manifest. A knob that stops here renders configs with the
// default and nobody notices until someone reads a generated file.
func TestClientKeepaliveReachesTheSpec(t *testing.T) {
	f := managedFleet()
	f.Masters[0].ClientAWG.Keepalive = "15-25"
	b, st := newBrokerWithFleet(t, f)
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	setWireVersion(t, st, "master-xa-1", api.WireClientWG)

	spec, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := spec.Master.ClientWG.Keepalive; got != "15-25" {
		t.Fatalf("client keepalive on the spec = %q, want %q", got, "15-25")
	}
}

// flakyClientStore fails exactly one call: listing client credentials.
type flakyClientStore struct {
	store.Store
	err error
}

func (f flakyClientStore) ListWGClients(context.Context, string) ([]domain.WGClient, error) {
	return nil, f.err
}

// A transient store failure must never render a client interface with no peers.
//
// That spec is VALID — an interface with zero credentials is a legitimate state —
// so nothing downstream would reject it, and the agent would apply it and drop
// every user at once. Failing the render instead leaves the node on its last-good
// config with all its peers, which is what "we could not find out" should mean.
func TestClientWGSpecFailsRatherThanEmptyingTheInterface(t *testing.T) {
	b, st, ctx := brokerWithManagedMaster(t)
	if _, err := b.IssueWGClient(ctx, "master-xa-1", "laptop"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Sanity: the peer is there before the store starts failing.
	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master.ClientWG == nil || len(spec.Master.ClientWG.Clients) != 1 {
		t.Fatalf("fixture is not exercising the path: %+v", spec.Master.ClientWG)
	}

	boom := errors.New("database is locked")
	b.store = flakyClientStore{Store: st, err: boom}
	spec, err = b.RenderNodeSpec(ctx, "master-xa-1")
	if err == nil {
		t.Fatalf("render succeeded despite an unreadable store; ClientWG = %+v", spec.Master.ClientWG)
	}
	if !errors.Is(err, boom) {
		t.Errorf("render error = %v, want it to wrap the store failure", err)
	}
}

// The other half of the same rule: nil is a COMMAND to hand the interface back to
// wg-easy, so it may only ever come from a decision the operator made — never from
// a failure. An agent too old to own the leg is such a decision.
func TestClientWGSpecNilOnlyOnDeliberateRelease(t *testing.T) {
	b, st, ctx := brokerWithManagedMaster(t)
	setWireVersion(t, st, "master-xa-1", api.WireClientWG-1)
	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("an agent below wire v8 is a supported state, not an error: %v", err)
	}
	if spec.Master.ClientWG != nil {
		t.Error("a pre-v8 agent must not be handed a client interface block")
	}
}

// The name is written verbatim into the live interface config, so the broker —
// the one write path every caller goes through — must apply the charset rule, not
// just a length bound. It checked only the length while its comment claimed
// otherwise, and the outer NodeSpec gate that used to catch this was removed
// because it froze the whole master.
func TestIssueWGClientRejectsAnInjectableName(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	for _, name := range []string{
		"laptop\n[Peer]\nAllowedIPs = 0.0.0.0/0",
		"laptop phone",
		"",
		strings.Repeat("a", domain.MaxClientNameLen+1),
	} {
		if _, err := b.IssueWGClient(ctx, "master-xa-1", name); err == nil {
			t.Errorf("IssueWGClient(%q) was accepted", name)
		}
	}
	c, err := b.IssueWGClient(ctx, "master-xa-1", "laptop-1.home_2")
	if err != nil {
		t.Fatalf("a legitimate name was rejected: %v", err)
	}
	if err := b.RenameWGClient(ctx, "master-xa-1", c.ID, "phone\nInjected = yes"); err == nil {
		t.Error("RenameWGClient accepted an injectable name")
	}
}

// A managed client interface must hand clients a resolver.
//
// ClientAWGDNS() falls back to the raw compose.client_dns manifest key, and that
// key is commented out in every shipped example because it "defaults to the exits'
// mgmt addresses" — a default that lives in composeSpec and that the managed path
// never consulted. So `client_awg.managed: true` on an un-edited manifest rendered
// configs with NO `DNS =` line at all, and the phone kept its carrier resolver:
// the two-tier DNS of ADR-0024 reached wg-easy's clients and stopped reaching ours.
func TestClientWGSpecHandsOutTheFleetResolver(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	// The manifest sets neither client_awg.dns nor compose.client_dns — the shipped
	// shape, and the one that produced a config with no DNS line.
	for i := range b.fleet.Masters {
		b.fleet.Masters[i].ClientAWG.DNS = nil
		b.fleet.Masters[i].Compose.ClientDNS = nil
		b.fleet.Masters[i].DNSFilter = true
	}

	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if spec.Master.ClientWG == nil {
		t.Fatal("no client interface rendered")
	}
	got := spec.Master.ClientWG.DNS
	if len(got) == 0 {
		t.Fatal("the client interface hands out no DNS at all; every client falls back to its carrier resolver")
	}
	// ADR-0024: with master-tier blocky the clients' single resolver is the master's
	// own address in the client pool, reached through the tunnel.
	if want := "10.80.0.1"; got[0] != want {
		t.Errorf("client DNS = %v, want the master gateway %q first", got, want)
	}
	// And it must agree with what the compose stack hands wg-easy's clients: two
	// renderers disagreeing about the resolver is how this broke in the first place.
	if compose := spec.Master.Compose.ClientDNS; len(compose) > 0 && compose[0] != got[0] {
		t.Errorf("compose hands out %v but the managed interface hands out %v", compose, got)
	}
}

// The IPv6 block is rendered as ONE thing or not at all.
//
// "::/0" tells the client to stop using its own IPv6 and send it here; ipv6_prefix
// is what lets the master answer. Rendering the route without the prefix — which is
// exactly what happens if an agent too old to understand the field is served one —
// abandons a working v6 path for one that drops silently: pages load then stall,
// video plays then freezes, and it reads as an MTU fault for days.
func TestClientWGSpecRendersTheIPv6BlockAsAWhole(t *testing.T) {
	b, st, ctx := brokerWithManagedMaster(t)
	for i := range b.fleet.Masters {
		b.fleet.Masters[i].ClientAWG.IPv6 = config.ClientIPv6Block
	}

	// Agent on the current wire: both halves.
	setWireVersion(t, st, "master-xa-1", api.WireClientIPv6)
	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cw := spec.Master.ClientWG
	if cw == nil {
		t.Fatal("no client interface")
	}
	if cw.IPv6Prefix == "" {
		t.Error("no ipv6_prefix: the master has no address to answer IPv6 from")
	}
	if !slices.Contains(cw.AllowedIPs, "::/0") {
		t.Errorf("no ::/0 in the client's AllowedIPs %v; the device keeps preferring its own IPv6", cw.AllowedIPs)
	}
	if err := cw.Validate(); err != nil {
		t.Errorf("the rendered spec does not validate: %v", err)
	}

	// Agent one version too old: NEITHER half. Not the route on its own.
	setWireVersion(t, st, "master-xa-1", api.WireClientIPv6-1)
	spec, err = b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cw = spec.Master.ClientWG
	if cw == nil {
		t.Fatal("no client interface")
	}
	if slices.Contains(cw.AllowedIPs, "::/0") {
		t.Errorf("an agent that cannot answer IPv6 was still told to hand out ::/0: %v", cw.AllowedIPs)
	}
	if cw.IPv6Prefix != "" {
		t.Errorf("ipv6_prefix %q rendered for an agent that drops the field", cw.IPv6Prefix)
	}
}

// And with the knob off, nothing about IPv6 appears at all.
func TestClientWGSpecOmitsIPv6WhenOff(t *testing.T) {
	b, _, ctx := brokerWithManagedMaster(t)
	spec, err := b.RenderNodeSpec(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	cw := spec.Master.ClientWG
	if cw.IPv6Prefix != "" || slices.Contains(cw.AllowedIPs, "::/0") {
		t.Errorf("IPv6 leaked into the default render: prefix=%q allowed=%v", cw.IPv6Prefix, cw.AllowedIPs)
	}
}

// The address the master's synthetic client holds must never be handed to a real
// one. It is reserved at issue time rather than checked afterwards: the store's
// UNIQUE constraint catches two clients colliding with each other, and cannot see
// a collision with a peer the agent adds locally.
func TestIssuedClientsNeverGetTheSyntheticAddress(t *testing.T) {
	pool := "10.73.0.0/29" // gateway .1, usable .1-.6, synthetic .6
	synth, err := domain.SyntheticClientAddress(pool)
	if err != nil {
		t.Fatalf("SyntheticClientAddress: %v", err)
	}
	var taken []string
	for {
		addr, aerr := domain.AllocateClientAddress(pool, []string{"10.73.0.1/32", synth}, taken)
		if aerr != nil {
			break
		}
		if addr == synth {
			t.Fatalf("the allocator issued the synthetic address %s to a client", synth)
		}
		taken = append(taken, addr)
		if len(taken) > 16 {
			t.Fatal("allocator did not terminate")
		}
	}
	if len(taken) == 0 {
		t.Fatal("no addresses were issuable at all")
	}
}
