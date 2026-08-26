package keybroker

import (
	"context"
	"errors"
	"strings"
	"testing"

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
	seedNode(t, st, "master-xa-1", "10.20.25.254", "203.0.113.1",
		"FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=", domain.RoleMaster)
	return b, st, context.Background()
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
