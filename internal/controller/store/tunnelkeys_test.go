package store

import (
	"context"
	"errors"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func tunnelKeyStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.UpsertNode(context.Background(), domain.Node{
		ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReconciling,
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestNodeTunnelKeysRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := tunnelKeyStore(t)

	if err := st.SetNodeTunnelKey(ctx, "master-xa-1", "anz3", "keyA"); err != nil {
		t.Fatalf("set anz3: %v", err)
	}
	if err := st.SetNodeTunnelKey(ctx, "master-xa-1", "vn1", "keyB"); err != nil {
		t.Fatalf("set vn1: %v", err)
	}

	keys, err := st.ListNodeTunnelKeys(ctx, "master-xa-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 || keys["anz3"] != "keyA" || keys["vn1"] != "keyB" {
		t.Fatalf("unexpected keys: %+v", keys)
	}

	// Re-publishing one tunnel is an upsert, not a second row.
	if err := st.SetNodeTunnelKey(ctx, "master-xa-1", "anz3", "keyA2"); err != nil {
		t.Fatalf("re-set anz3: %v", err)
	}
	keys, err = st.ListNodeTunnelKeys(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["anz3"] != "keyA2" {
		t.Fatalf("upsert did not replace in place: %+v", keys)
	}
}

func TestListNodeTunnelKeysUnknownNodeIsEmptyNotError(t *testing.T) {
	// Callers render peers from whatever is registered so far; an unknown or
	// not-yet-publishing master must degrade to the legacy key, not fail the render.
	keys, err := tunnelKeyStore(t).ListNodeTunnelKeys(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("want no error for an unknown node, got %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("want no keys, got %+v", keys)
	}
}

func TestSetNodeTunnelKeyRejectsUnknownNodeAndEmptyArgs(t *testing.T) {
	ctx := context.Background()
	st := tunnelKeyStore(t)

	if err := st.SetNodeTunnelKey(ctx, "nobody", "anz3", "keyA"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound for an unregistered node, got %v", err)
	}
	if err := st.SetNodeTunnelKey(ctx, "", "anz3", "keyA"); err == nil {
		t.Fatal("want an error for an empty node ID")
	}
	if err := st.SetNodeTunnelKey(ctx, "master-xa-1", "", "keyA"); err == nil {
		t.Fatal("want an error for an empty tunnel")
	}
}

func TestDeletingANodeCascadesItsTunnelKeys(t *testing.T) {
	ctx := context.Background()
	st := tunnelKeyStore(t)
	if err := st.SetNodeTunnelKey(ctx, "master-xa-1", "anz3", "keyA"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteNode(ctx, "master-xa-1"); err != nil {
		t.Fatal(err)
	}
	keys, err := st.ListNodeTunnelKeys(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("tunnel keys outlived their node: %+v", keys)
	}
}
