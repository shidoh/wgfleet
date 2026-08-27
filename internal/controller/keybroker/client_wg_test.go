package keybroker

import (
	"context"
	"errors"
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

	for i := range 5 {
		if _, err := b.IssueWGClient(ctx, "master-xa-1", string(rune('a'+i))); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	_, err := b.IssueWGClient(ctx, "master-xa-1", "overflow")
	if !errors.Is(err, domain.ErrPoolExhausted) {
		t.Fatalf("issue into a full pool = %v, want ErrPoolExhausted", err)
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
	if cw.AWG == nil || cw.ClientAWGLocal == nil {
		t.Fatal("client interface must carry both ends of the AWG profile")
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
	if cw.ClientAWGLocal == nil {
		t.Fatal("the client end lost its own local profile")
	}
	// The local half differs per end by design; the shared half must not.
	rendered := *cw.AWG
	rendered.Local = *cw.ClientAWGLocal
	if rendered.Shared != cw.AWG.Shared {
		t.Fatal("the client config would carry different shared params than the interface")
	}
	if rendered.Shared.HeaderProtectionKey == "" {
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
