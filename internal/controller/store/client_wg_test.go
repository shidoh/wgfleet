package store

import (
	"context"
	"errors"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func wgClient(id, name, addr string) domain.WGClient {
	return domain.WGClient{
		ID:         id,
		Name:       name,
		Address:    addr,
		PublicKey:  "pub-" + id,
		PrivateKey: "priv-" + id,
		Enabled:    true,
	}
}

// storeWithMaster returns a store holding one registered master, the precondition
// for every credential operation (the FK would reject the insert otherwise).
func storeWithMaster(t *testing.T) (*SQLiteStore, context.Context) {
	t.Helper()
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.UpsertNode(ctx, masterNode()); err != nil {
		t.Fatalf("upsert master: %v", err)
	}
	return s, ctx
}

func TestWGClientAddAndList(t *testing.T) {
	s, ctx := storeWithMaster(t)

	// Deliberately added out of name order: the listing must be stable, because
	// the spec render feeds it into a config diff that would otherwise churn.
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("b", "phone", "10.8.0.3/32")); err != nil {
		t.Fatalf("add phone: %v", err)
	}
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add laptop: %v", err)
	}

	got, err := s.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list returned %d clients, want 2: %+v", len(got), got)
	}
	if got[0].Name != "laptop" || got[1].Name != "phone" {
		t.Fatalf("list order = %q, %q; want laptop, phone", got[0].Name, got[1].Name)
	}
	if got[0].PrivateKey != "priv-a" || got[0].PublicKey != "pub-a" || got[0].Address != "10.8.0.2/32" {
		t.Fatalf("laptop round-trip = %+v", got[0])
	}
	if !got[0].Enabled {
		t.Error("laptop came back disabled, want enabled")
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, want the issue timestamp")
	}
}

func TestWGClientAddRequiresRegisteredMaster(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("add against an unregistered master = %v, want ErrNotFound", err)
	}
}

func TestWGClientAddRejectsIncomplete(t *testing.T) {
	s, ctx := storeWithMaster(t)
	tests := map[string]domain.WGClient{
		"missing id":         {Name: "laptop", Address: "10.8.0.2/32", PublicKey: "pub", PrivateKey: "priv"},
		"missing name":       {ID: "a", Address: "10.8.0.2/32", PublicKey: "pub", PrivateKey: "priv"},
		"missing address":    {ID: "a", Name: "laptop", PublicKey: "pub", PrivateKey: "priv"},
		"missing public key": {ID: "a", Name: "laptop", Address: "10.8.0.2/32", PrivateKey: "priv"},
	}
	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.AddWGClient(ctx, "master-xa-1", c); err == nil {
				t.Fatal("AddWGClient() = nil, want an error")
			}
		})
	}
}

// Two credentials may not share a name or an address on one master: the first
// would confuse the operator, the second would put two clients on one tunnel
// address. Both are enforced by the schema so no code path can bypass them.
func TestWGClientRejectsDuplicates(t *testing.T) {
	s, ctx := storeWithMaster(t)
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("b", "laptop", "10.8.0.3/32")); err == nil {
		t.Error("duplicate name accepted, want an error")
	}
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("c", "tablet", "10.8.0.2/32")); err == nil {
		t.Error("duplicate address accepted, want an error")
	}
}

func TestWGClientSetEnabled(t *testing.T) {
	s, ctx := storeWithMaster(t)
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.SetWGClientEnabled(ctx, "master-xa-1", "a", false); err != nil {
		t.Fatalf("mute: %v", err)
	}
	got, err := s.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got[0].Enabled {
		t.Error("client still enabled after muting")
	}
	// Muting keeps the credential intact — that is the whole point: the user's
	// config stays valid, only the peer leaves the interface.
	if got[0].PrivateKey != "priv-a" || got[0].Address != "10.8.0.2/32" {
		t.Errorf("muting altered the credential: %+v", got[0])
	}
	if err := s.SetWGClientEnabled(ctx, "master-xa-1", "missing", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("mute of an unknown client = %v, want ErrNotFound", err)
	}
}

// Renaming must not touch keys or the address: identity is the id, the name is a
// label (ADR-0028).
func TestWGClientRename(t *testing.T) {
	s, ctx := storeWithMaster(t)
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.RenameWGClient(ctx, "master-xa-1", "a", "work-laptop"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := s.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got[0].Name != "work-laptop" {
		t.Fatalf("Name = %q, want work-laptop", got[0].Name)
	}
	if got[0].ID != "a" || got[0].PublicKey != "pub-a" || got[0].Address != "10.8.0.2/32" {
		t.Fatalf("rename altered identity or keys: %+v", got[0])
	}
	if err := s.RenameWGClient(ctx, "master-xa-1", "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rename of an unknown client = %v, want ErrNotFound", err)
	}
}

func TestWGClientRemove(t *testing.T) {
	s, ctx := storeWithMaster(t)
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.RemoveWGClient(ctx, "master-xa-1", "a"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, err := s.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("list returned %d clients after removal, want 0", len(got))
	}
	if err := s.RemoveWGClient(ctx, "master-xa-1", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second remove = %v, want ErrNotFound", err)
	}
}

// Credentials belong to their master: deleting the node destroys them rather
// than leaving orphaned secrets behind (spec §9).
func TestWGClientCascadesWithTheMaster(t *testing.T) {
	s, ctx := storeWithMaster(t)
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.DeleteNode(ctx, "master-xa-1"); err != nil {
		t.Fatalf("delete node: %v", err)
	}
	got, err := s.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("list returned %d clients after the master was deleted, want 0", len(got))
	}
}

// Two masters keep separate credential sets — the precondition for multi-master
// (ADR-0027), where the same person holds one credential per gateway.
func TestWGClientIsScopedToItsMaster(t *testing.T) {
	s, ctx := storeWithMaster(t)
	second := masterNode()
	second.ID, second.Name = "master-xa-2", "master-xa-2"
	if err := s.UpsertNode(ctx, second); err != nil {
		t.Fatalf("upsert second master: %v", err)
	}
	if err := s.AddWGClient(ctx, "master-xa-1", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add on first: %v", err)
	}
	// Same id, name and address on the other master: legal, they are different pools.
	if err := s.AddWGClient(ctx, "master-xa-2", wgClient("a", "laptop", "10.8.0.2/32")); err != nil {
		t.Fatalf("add on second: %v", err)
	}
	first, err := s.ListWGClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list first: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("first master has %d clients, want 1", len(first))
	}
	if err := s.RemoveWGClient(ctx, "master-xa-1", "a"); err != nil {
		t.Fatalf("remove from first: %v", err)
	}
	secondList, err := s.ListWGClients(ctx, "master-xa-2")
	if err != nil {
		t.Fatalf("list second: %v", err)
	}
	if len(secondList) != 1 {
		t.Fatalf("removing from one master affected the other: %d clients left", len(secondList))
	}
}
