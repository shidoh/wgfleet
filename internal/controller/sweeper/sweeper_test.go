package sweeper

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func newSweeper(t *testing.T, threshold time.Duration, now time.Time) (*Sweeper, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := New(st, threshold, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = func() time.Time { return now }
	return s, st
}

func seedNode(t *testing.T, st store.Store, id string, state domain.NodeState, lastSeen time.Time) {
	t.Helper()
	if err := st.UpsertNode(context.Background(), domain.Node{
		ID: id, Name: id, Role: domain.RoleExit, State: state, LastSeen: lastSeen,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSweepDemotesStaleReady(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, st := newSweeper(t, 3*time.Minute, now)
	ctx := context.Background()

	seedNode(t, st, "stale-ready", domain.StateReady, now.Add(-5*time.Minute))        // stale → demote
	seedNode(t, st, "fresh-ready", domain.StateReady, now.Add(-30*time.Second))       // fresh → keep
	seedNode(t, st, "stale-recon", domain.StateReconciling, now.Add(-10*time.Minute)) // stale → demote

	n, err := s.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("demoted %d, want 2", n)
	}

	sr, _ := st.GetNode(ctx, "stale-ready")
	if sr.State != domain.StateDegraded || sr.LastError == "" {
		t.Errorf("stale-ready not demoted: %+v", sr)
	}
	fr, _ := st.GetNode(ctx, "fresh-ready")
	if fr.State != domain.StateReady {
		t.Errorf("fresh-ready should stay Ready, got %q", fr.State)
	}
	rc, _ := st.GetNode(ctx, "stale-recon")
	if rc.State != domain.StateDegraded {
		t.Errorf("stale-recon should be Degraded, got %q", rc.State)
	}
}

func TestSweepLeavesIneligibleStates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, st := newSweeper(t, 1*time.Minute, now)
	ctx := context.Background()

	old := now.Add(-1 * time.Hour)
	seedNode(t, st, "pending", domain.StatePending, time.Time{})
	seedNode(t, st, "provisioning", domain.StateProvisioning, time.Time{})
	seedNode(t, st, "error", domain.StateError, old)
	seedNode(t, st, "degraded", domain.StateDegraded, old)

	n, err := s.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("should not demote ineligible states, demoted %d", n)
	}
	for _, id := range []string{"pending", "provisioning", "error", "degraded"} {
		got, _ := st.GetNode(ctx, id)
		if got.State == domain.StateDegraded && id != "degraded" {
			t.Errorf("%s was wrongly demoted", id)
		}
	}
}

func TestSweepUsesUpdatedAtWhenNeverReported(t *testing.T) {
	// A node that registered (Reconciling) but never reported has zero LastSeen;
	// the sweep falls back to UpdatedAt. The in-memory store stamps UpdatedAt to
	// "now" on upsert, so with a far-future sweep clock it is stale.
	now := time.Unix(2_000_000_000, 0) // far ahead of upsert time
	s, st := newSweeper(t, 1*time.Minute, now)
	ctx := context.Background()
	seedNode(t, st, "registered-died", domain.StateReconciling, time.Time{})

	n, err := s.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("registered-but-silent node should be demoted, demoted %d", n)
	}
}

func TestSweepNoChangeWhenAllFresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, st := newSweeper(t, 3*time.Minute, now)
	seedNode(t, st, "a", domain.StateReady, now.Add(-10*time.Second))
	n, err := s.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("no demotions expected, got %d", n)
	}
}
