package keybroker

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// countingStore counts the key writes that reach the store seam. Agents republish
// every key on every reconcile pass, so a republish of an UNCHANGED key must not
// produce a write: it is pure WAL churn today and a replicated raft command under
// ADR-0027 phase B.
type countingStore struct {
	store.Store
	wg, reality, clientVless, tunnel int
}

func (c *countingStore) SetNodePublicKey(ctx context.Context, id, publicKey string) error {
	c.wg++
	return c.Store.SetNodePublicKey(ctx, id, publicKey)
}

func (c *countingStore) SetNodeRealityKey(ctx context.Context, id, publicKey string) error {
	c.reality++
	return c.Store.SetNodeRealityKey(ctx, id, publicKey)
}

func (c *countingStore) SetNodeClientVlessKey(ctx context.Context, id, publicKey string) error {
	c.clientVless++
	return c.Store.SetNodeClientVlessKey(ctx, id, publicKey)
}

func (c *countingStore) SetNodeTunnelKey(ctx context.Context, id, tunnel, publicKey string) error {
	c.tunnel++
	return c.Store.SetNodeTunnelKey(ctx, id, tunnel, publicKey)
}

func newCountingBroker(t *testing.T) (*Broker, *countingStore) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cs := &countingStore{Store: st}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cs, testFleet(), log), cs
}

const (
	wgKeyA      = "A/3Hs1FWpM4iZiG09od1cESePk+PiG2Tg1jKlvX3BFY="
	wgKeyB      = "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc="
	realityKeyA = "GG-oHnhP6yXpNjbnGl0Y3wJHi1i5FPTakiSPBS8VJXE"
	realityKeyB = "kJmXwNVv2tYSyOd8gEeQMPTMArlnG-EPvJKX2lNSHXg"
)

func TestRegisterKeysAreWriteDeduped(t *testing.T) {
	ctx := context.Background()
	b, cs := newCountingBroker(t)
	seedNode(t, cs, "exit-de-1", "10.20.0.5", "198.51.100.7", "", domain.RoleExit)
	seedNode(t, cs, "master-xa-1", "10.20.25.254", "203.0.113.1", "", domain.RoleMaster)

	// Three passes with the same keys: exactly one write each, then silence.
	for range 3 {
		if err := b.RegisterPublicKey(ctx, "exit-de-1", wgKeyA); err != nil {
			t.Fatalf("RegisterPublicKey: %v", err)
		}
		if err := b.RegisterRealityKey(ctx, "exit-de-1", realityKeyA); err != nil {
			t.Fatalf("RegisterRealityKey: %v", err)
		}
		if err := b.RegisterClientVlessKey(ctx, "master-xa-1", realityKeyA); err != nil {
			t.Fatalf("RegisterClientVlessKey: %v", err)
		}
		if err := b.RegisterTunnelKey(ctx, "master-xa-1", "exit-de-1", wgKeyB); err != nil {
			t.Fatalf("RegisterTunnelKey: %v", err)
		}
	}
	if cs.wg != 1 || cs.reality != 1 || cs.clientVless != 1 || cs.tunnel != 1 {
		t.Fatalf("writes after 3 identical passes = wg:%d reality:%d clientVless:%d tunnel:%d, want 1 each",
			cs.wg, cs.reality, cs.clientVless, cs.tunnel)
	}

	// A genuine rotation must still get through.
	if err := b.RegisterPublicKey(ctx, "exit-de-1", wgKeyB); err != nil {
		t.Fatalf("RegisterPublicKey rotate: %v", err)
	}
	if err := b.RegisterRealityKey(ctx, "exit-de-1", realityKeyB); err != nil {
		t.Fatalf("RegisterRealityKey rotate: %v", err)
	}
	if err := b.RegisterTunnelKey(ctx, "master-xa-1", "exit-de-1", wgKeyA); err != nil {
		t.Fatalf("RegisterTunnelKey rotate: %v", err)
	}
	if cs.wg != 2 || cs.reality != 2 || cs.tunnel != 2 {
		t.Fatalf("writes after rotation = wg:%d reality:%d tunnel:%d, want 2 each", cs.wg, cs.reality, cs.tunnel)
	}

	node, err := cs.GetNode(ctx, "exit-de-1")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if node.PublicKey != wgKeyB || node.RealityPublicKey != realityKeyB {
		t.Fatalf("rotated keys not stored: wg=%q reality=%q", node.PublicKey, node.RealityPublicKey)
	}
}

// The dedup must not swallow the not-registered error: an unknown node still has
// to reach the store so the gRPC layer can map ErrNotFound to FailedPrecondition.
func TestRegisterPublicKeyUnknownNodeStillErrors(t *testing.T) {
	b, cs := newCountingBroker(t)
	if err := b.RegisterPublicKey(context.Background(), "ghost", wgKeyA); err == nil {
		t.Fatal("RegisterPublicKey for unknown node: want error, got nil")
	}
	if cs.wg != 1 {
		t.Errorf("store write attempts = %d, want 1 (the error must come from the store)", cs.wg)
	}
}
