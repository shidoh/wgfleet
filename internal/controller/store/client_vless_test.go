package store

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func masterNode() domain.Node {
	return domain.Node{
		ID:       "master-xa-1",
		Name:     "master-xa-1",
		Role:     domain.RoleMaster,
		MgmtAddr: "10.20.0.1",
		PublicIP: "203.0.113.1",
		State:    domain.StatePending,
	}
}

func TestClientVlessPublicKeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.UpsertNode(ctx, masterNode()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.SetNodeClientVlessKey(ctx, "master-xa-1", "PUBKEYBASE64"); err != nil {
		t.Fatalf("set client vless key: %v", err)
	}
	got, err := s.GetNode(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientVLESSPublicKey != "PUBKEYBASE64" {
		t.Errorf("ClientVLESSPublicKey = %q, want PUBKEYBASE64", got.ClientVLESSPublicKey)
	}
	// An upsert must not clobber the stored key (COALESCE-style preservation is not
	// used here, but the column is carried through the upsert values).
	n := masterNode()
	n.ClientVLESSPublicKey = "PUBKEYBASE64"
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, _ = s.GetNode(ctx, "master-xa-1")
	if got.ClientVLESSPublicKey != "PUBKEYBASE64" {
		t.Errorf("key lost across upsert: %q", got.ClientVLESSPublicKey)
	}
}

func TestVLESSClientCRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.UpsertNode(ctx, masterNode()); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Empty list for an unknown master is not an error.
	if got, err := s.ListVLESSClients(ctx, "nope"); err != nil || len(got) != 0 {
		t.Fatalf("list unknown = %v, %v; want empty, nil", got, err)
	}

	add := func(name, uuid, sid string) {
		if err := s.AddVLESSClient(ctx, "master-xa-1", domain.VLESSClient{Name: name, UUID: uuid, ShortID: sid}); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	add("bob", "uuid-b", "sidb")
	add("alice", "uuid-a", "sida")

	got, err := s.ListVLESSClients(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Ordered by name.
	if len(got) != 2 || got[0].Name != "alice" || got[1].Name != "bob" {
		t.Fatalf("list = %+v, want [alice bob]", got)
	}
	if got[0].UUID != "uuid-a" || got[0].ShortID != "sida" {
		t.Errorf("alice round-trip = %+v", got[0])
	}

	// Re-adding the same name replaces its credential (idempotent upsert).
	add("alice", "uuid-a2", "sida2")
	got, _ = s.ListVLESSClients(ctx, "master-xa-1")
	if len(got) != 2 || got[0].UUID != "uuid-a2" {
		t.Errorf("re-add did not replace: %+v", got)
	}

	// Revoke.
	if err := s.RevokeVLESSClient(ctx, "master-xa-1", "bob"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ = s.ListVLESSClients(ctx, "master-xa-1")
	if len(got) != 1 || got[0].Name != "alice" {
		t.Errorf("after revoke = %+v, want [alice]", got)
	}
	// Revoking an absent client is ErrNotFound.
	if err := s.RevokeVLESSClient(ctx, "master-xa-1", "ghost"); err != ErrNotFound {
		t.Errorf("revoke absent = %v, want ErrNotFound", err)
	}
}

func TestAddVLESSClientUnknownMaster(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	err := s.AddVLESSClient(ctx, "ghost", domain.VLESSClient{Name: "x", UUID: "u"})
	if err != ErrNotFound {
		t.Errorf("add to unknown master = %v, want ErrNotFound", err)
	}
}
