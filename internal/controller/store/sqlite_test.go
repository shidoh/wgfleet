package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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

func TestAuthCredentialLifecycle(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	// Unset initially.
	if ok, err := st.AuthConfigured(ctx); err != nil || ok {
		t.Fatalf("AuthConfigured on empty store = %v, %v; want false, nil", ok, err)
	}
	if _, err := st.GetAuth(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAuth on empty store: want ErrNotFound, got %v", err)
	}

	// Set the credential.
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := st.SetAuthCredential(ctx, "admin", "hash-v1", secret); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.AuthConfigured(ctx); !ok {
		t.Fatal("AuthConfigured after set = false")
	}
	rec, err := st.GetAuth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Username != "admin" || rec.PasswordHash != "hash-v1" || string(rec.SessionSecret) != string(secret) {
		t.Fatalf("GetAuth = %+v", rec)
	}
	if rec.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not set")
	}

	// Change password rotates hash + secret, keeps username.
	newSecret := []byte("ffffffffffffffffffffffffffffffff")
	if err := st.SetAuthPassword(ctx, "hash-v2", newSecret); err != nil {
		t.Fatal(err)
	}
	rec, _ = st.GetAuth(ctx)
	if rec.Username != "admin" || rec.PasswordHash != "hash-v2" || string(rec.SessionSecret) != string(newSecret) {
		t.Fatalf("after SetAuthPassword: %+v", rec)
	}
}

func TestSetAuthPasswordMissingRow(t *testing.T) {
	st, _ := Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetAuthPassword(context.Background(), "h", []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetAuthPassword with no row: want ErrNotFound, got %v", err)
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

func TestStatusExitHealthPersists(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
	want := domain.NodeStatus{
		NodeID: "master-xa-1", State: domain.StateReady,
		ExitHealth: []domain.ExitTunnelHealth{
			{Name: "exit-de-1", Alive: true, Delay: 42 * time.Millisecond, LastTest: time.Unix(1000, 0).UTC(), Selected: true},
		},
	}
	if err := st.RecordStatus(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetStatus(ctx, "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ExitHealth) != 1 || got.ExitHealth[0].Name != "exit-de-1" || !got.ExitHealth[0].Alive ||
		got.ExitHealth[0].Delay != 42*time.Millisecond || !got.ExitHealth[0].Selected {
		t.Fatalf("exit health not persisted: %+v", got.ExitHealth)
	}
}

// Rolling the controller back must not destroy the way forward.
//
// The stamp used to be written unconditionally, so an older binary opening a
// newer database lowered user_version to its own count. Rolling forward then
// replayed migrations that had already run — `duplicate column name` — and
// store.Open failed for good, which with Restart=on-failure is a crash loop of
// the whole control plane. Refusing the newer database keeps the rollback path
// intact: one clear error, and the operator's data untouched.
func TestOpenRefusesADatabaseFromANewerBuild(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Pretend a newer build wrote this database.
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", len(migrations)+1)); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("Open() accepted a database written by a newer build")
	} else if !strings.Contains(err.Error(), "newer wgfleet-controller") {
		t.Errorf("Open() = %v, want an error naming the cause and the way out", err)
	}

	// And the refusal must not have rewritten the stamp on its way out — otherwise
	// it would have done the very damage it exists to prevent.
	s2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen raw: %v", err)
	}
	defer s2.Close()
	var v int
	if err := s2.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if want := len(migrations) + 1; v != want {
		t.Errorf("user_version = %d after a refused open, want it left at %d", v, want)
	}
}

// The real rollback, end to end: an OLD binary stamps the version down (it has no
// guard and never will), and the way FORWARD must still work. Before the
// migrations were made replayable this failed with `duplicate column name` and
// the store never opened again.
func TestRollForwardAfterAnOldBinaryLoweredTheStamp(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.UpsertNode(ctx, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// What an older controller does on open: run the migrations it knows, then
	// stamp its own count — unconditionally, downwards.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := old.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", len(migrations)-3)); err != nil {
		t.Fatalf("lower stamp: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	forward, err := Open(path)
	if err != nil {
		t.Fatalf("rolling forward after a lowered stamp failed: %v", err)
	}
	defer forward.Close()

	// The stamp is repaired and the data is intact.
	var v int
	if err := forward.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if v != len(migrations) {
		t.Errorf("user_version = %d after rolling forward, want %d", v, len(migrations))
	}
	if _, err := forward.GetNode(ctx, "master-xa-1"); err != nil {
		t.Errorf("the node did not survive the rollback: %v", err)
	}
}

// A deleted node is refused readmission until an operator provisions it again:
// deleting it used to be undone by the node's own next Register.
func TestDeleteRetiresTheNodeUntilReadmitted(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{ID: "exit-x", Name: "exit-x", Role: domain.RoleExit}); err != nil {
		t.Fatal(err)
	}
	if r, _ := st.Retired(ctx, "exit-x"); r {
		t.Fatal("a live node reads as retired")
	}
	if err := st.DeleteNode(ctx, "exit-x"); err != nil {
		t.Fatal(err)
	}
	if r, err := st.Retired(ctx, "exit-x"); err != nil || !r {
		t.Fatalf("deleted node not retired: %v %v", r, err)
	}
	if err := st.Readmit(ctx, "exit-x"); err != nil {
		t.Fatal(err)
	}
	if r, _ := st.Retired(ctx, "exit-x"); r {
		t.Fatal("readmitted node still retired")
	}
}
