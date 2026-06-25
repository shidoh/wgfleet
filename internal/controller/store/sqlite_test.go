package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleNode() domain.Node {
	return domain.Node{
		ID:       "exit-de-1",
		Name:     "exit-de-1",
		Role:     domain.RoleExit,
		Region:   "de",
		MgmtAddr: "10.20.0.5",
		PublicIP: "203.0.113.10",
		State:    domain.StatePending,
		SSH:      domain.SSHTarget{Host: "203.0.113.10", Port: 22, User: "root", KeyPath: "/tmp/k"},
	}
}

func TestUpsertAndGetNode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := s.GetNode(ctx, n.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != n.Name || got.Role != domain.RoleExit || got.Region != "de" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.SSH.Port != 22 || got.SSH.User != "root" {
		t.Errorf("ssh round-trip mismatch: %+v", got.SSH)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("timestamps should be set on insert")
	}
}

func TestUpsertRoundTripsAgentVersion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	n := sampleNode()
	n.AgentVersion = "v1.2.3+abc123"
	n.WireVersion = 7
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.GetNode(ctx, n.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AgentVersion != "v1.2.3+abc123" || got.WireVersion != 7 {
		t.Errorf("agent version round-trip mismatch: %q wire=%d", got.AgentVersion, got.WireVersion)
	}
}

func TestMigrateIsIdempotentAcrossReopen(t *testing.T) {
	// A file-backed store, reopened, must re-run migrate() without error — the
	// ALTER TABLE migrations would fail if run twice without user_version gating.
	path := t.TempDir() + "/state.db"
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := s1.UpsertNode(context.Background(), sampleNode()); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	_ = s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if _, err := s2.GetNode(context.Background(), "exit-de-1"); err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
}

func TestUpsertPreservesCreatedAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	first, _ := s.GetNode(ctx, n.ID)

	// Re-upsert with a different name; created_at must survive.
	n.Name = "exit-de-1-renamed"
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	second, _ := s.GetNode(ctx, n.ID)

	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at changed on update: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	if second.Name != "exit-de-1-renamed" {
		t.Errorf("name not updated: %q", second.Name)
	}
}

func TestGetNodeNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetNode(context.Background(), "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestListNodesOrdered(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, name := range []string{"exit-z", "exit-a", "exit-m"} {
		n := sampleNode()
		n.ID, n.Name = name, name
		if err := s.UpsertNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"exit-a", "exit-m", "exit-z"}
	if len(nodes) != len(want) {
		t.Fatalf("got %d nodes, want %d", len(nodes), len(want))
	}
	for i, n := range nodes {
		if n.Name != want[i] {
			t.Errorf("position %d: got %q want %q", i, n.Name, want[i])
		}
	}
}

func TestSetNodeStateAndPublicKey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}

	if err := s.SetNodeState(ctx, n.ID, domain.StateReady, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodePublicKey(ctx, n.ID, "PUBKEY=="); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	if got.State != domain.StateReady {
		t.Errorf("state = %q", got.State)
	}
	if got.PublicKey != "PUBKEY==" {
		t.Errorf("public key = %q", got.PublicKey)
	}

	// Operations on a missing node must report ErrNotFound.
	if err := s.SetNodeState(ctx, "ghost", domain.StateReady, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodeState ghost: want ErrNotFound, got %v", err)
	}
	if err := s.SetNodePublicKey(ctx, "ghost", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodePublicKey ghost: want ErrNotFound, got %v", err)
	}
}

func TestRecordAndGetStatus(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}

	hs := time.Now().Add(-30 * time.Second).UTC().Truncate(time.Nanosecond)
	st := domain.NodeStatus{
		NodeID:        n.ID,
		State:         domain.StateReady,
		LastHandshake: hs,
		EgressIP:      "104.16.0.1",
		Checks: []domain.HealthCheck{
			{Name: "warp-egress", OK: true, Detail: "cloudflare", Latency: 50 * time.Millisecond},
			{Name: "dns", OK: true},
		},
	}
	if err := s.RecordStatus(ctx, st); err != nil {
		t.Fatalf("record status: %v", err)
	}

	got, err := s.GetStatus(ctx, n.ID)
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	if got.State != domain.StateReady || got.EgressIP != "104.16.0.1" {
		t.Errorf("status mismatch: %+v", got)
	}
	if len(got.Checks) != 2 || got.Checks[0].Name != "warp-egress" || !got.Checks[0].OK {
		t.Errorf("checks round-trip mismatch: %+v", got.Checks)
	}
	if !got.LastHandshake.Equal(hs) {
		t.Errorf("handshake = %v, want %v", got.LastHandshake, hs)
	}

	// RecordStatus must also stamp last_seen on the node.
	node, _ := s.GetNode(ctx, n.ID)
	if node.LastSeen.IsZero() {
		t.Error("last_seen not stamped after RecordStatus")
	}
}

func TestRecordStatusOverwrites(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	_ = s.UpsertNode(ctx, n)

	_ = s.RecordStatus(ctx, domain.NodeStatus{NodeID: n.ID, State: domain.StateDegraded})
	_ = s.RecordStatus(ctx, domain.NodeStatus{NodeID: n.ID, State: domain.StateReady})

	got, _ := s.GetStatus(ctx, n.ID)
	if got.State != domain.StateReady {
		t.Errorf("latest status = %q, want Ready", got.State)
	}
}

func TestDeleteNodeCascadesStatus(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	_ = s.UpsertNode(ctx, n)
	_ = s.RecordStatus(ctx, domain.NodeStatus{NodeID: n.ID, State: domain.StateReady})

	if err := s.DeleteNode(ctx, n.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetNode(ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("node still present: %v", err)
	}
	if _, err := s.GetStatus(ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("status not cascaded: %v", err)
	}
	if err := s.DeleteNode(ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete: want ErrNotFound, got %v", err)
	}
}

func TestUpsertRequiresID(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertNode(context.Background(), domain.Node{}); err == nil {
		t.Fatal("expected error for empty node ID")
	}
}

func TestSetNodeDrain(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetNode(ctx, n.ID); got.Drain {
		t.Error("new node should not be draining")
	}
	if err := s.SetNodeDrain(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	if !got.Drain {
		t.Error("drain flag not persisted")
	}
	// Upsert must preserve the drain flag round-trip.
	got.Region = "nl"
	_ = s.UpsertNode(ctx, got)
	again, _ := s.GetNode(ctx, n.ID)
	if !again.Drain {
		t.Error("drain flag lost on upsert")
	}
	if err := s.SetNodeDrain(ctx, "ghost", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodeDrain ghost: want ErrNotFound, got %v", err)
	}
}

func TestSetNodeDecommission(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	_ = s.UpsertNode(ctx, n)
	if err := s.SetNodeDecommission(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	if !got.Decommission {
		t.Error("decommission flag not persisted")
	}
	// Drain and decommission are independent.
	if got.Drain {
		t.Error("decommission must not set drain")
	}
}

func TestSetNodeRealityKey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodePublicKey(ctx, n.ID, "WGKEY=="); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeRealityKey(ctx, n.ID, "REALITYKEY"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	// The two key registries are independent.
	if got.PublicKey != "WGKEY==" {
		t.Errorf("wg key clobbered: %q", got.PublicKey)
	}
	if got.RealityPublicKey != "REALITYKEY" {
		t.Errorf("reality key = %q, want REALITYKEY", got.RealityPublicKey)
	}
	// A re-register (GetNode→UpsertNode) preserves both keys.
	got.PublicIP = "203.0.113.99"
	if err := s.UpsertNode(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := s.GetNode(ctx, n.ID)
	if again.RealityPublicKey != "REALITYKEY" || again.PublicKey != "WGKEY==" {
		t.Errorf("keys lost across upsert: wg=%q reality=%q", again.PublicKey, again.RealityPublicKey)
	}
	if err := s.SetNodeRealityKey(ctx, "ghost", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodeRealityKey ghost: want ErrNotFound, got %v", err)
	}
}
