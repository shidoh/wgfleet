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

func TestSetNodeLifelineKey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	n := sampleNode()
	if err := s.UpsertNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodePublicKey(ctx, n.ID, "WGKEY=="); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeLifelineKey(ctx, n.ID, "LIFELINEKEY"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNode(ctx, n.ID)
	// The two key registries are independent.
	if got.PublicKey != "WGKEY==" {
		t.Errorf("wg key clobbered: %q", got.PublicKey)
	}
	if got.LifelinePublicKey != "LIFELINEKEY" {
		t.Errorf("lifeline key = %q, want LIFELINEKEY", got.LifelinePublicKey)
	}
	// A re-register (GetNode→UpsertNode) preserves both keys.
	got.PublicIP = "203.0.113.99"
	if err := s.UpsertNode(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := s.GetNode(ctx, n.ID)
	if again.LifelinePublicKey != "LIFELINEKEY" || again.PublicKey != "WGKEY==" {
		t.Errorf("keys lost across upsert: wg=%q lifeline=%q", again.PublicKey, again.LifelinePublicKey)
	}
	if err := s.SetNodeLifelineKey(ctx, "ghost", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetNodeLifelineKey ghost: want ErrNotFound, got %v", err)
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

// The controller arms the master's gate for an exit-initiated tunnel only after
// the exit reported the pinned endpoint; a value lost between report and render
// would leave the gate unarmed forever.
func TestStatusAWGMasterEndpointPersists(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{ID: "exit-a", Name: "exit-a", Role: domain.RoleExit, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordStatus(ctx, domain.NodeStatus{NodeID: "exit-a", State: domain.StateReady, AWGMasterEndpoint: "192.0.2.10:41234"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetStatus(ctx, "exit-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.AWGMasterEndpoint != "192.0.2.10:41234" {
		t.Fatalf("AWGMasterEndpoint = %q after round trip, want 192.0.2.10:41234", got.AWGMasterEndpoint)
	}
}

// An exit reports an empty endpoint whenever it cannot read its interface — right
// after an agent restart, on an error report, when `awg show` fails. The master's
// gate is armed from this column, so an empty report must not erase what the exit
// last confirmed; a DIFFERENT endpoint still replaces it.
func TestStatusAWGMasterEndpointSurvivesAnEmptyReport(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.UpsertNode(ctx, domain.Node{ID: "exit-a", Name: "exit-a", Role: domain.RoleExit, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
	record := func(ep string) string {
		t.Helper()
		if err := st.RecordStatus(ctx, domain.NodeStatus{NodeID: "exit-a", State: domain.StateReady, AWGMasterEndpoint: ep}); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetStatus(ctx, "exit-a")
		if err != nil {
			t.Fatal(err)
		}
		return got.AWGMasterEndpoint
	}
	if got := record("192.0.2.10:41234"); got != "192.0.2.10:41234" {
		t.Fatalf("first report: %q", got)
	}
	if got := record(""); got != "192.0.2.10:41234" {
		t.Fatalf("empty report erased the confirmed endpoint: %q", got)
	}
	if got := record("192.0.2.10:51514"); got != "192.0.2.10:51514" {
		t.Fatalf("a different endpoint must replace it: %q", got)
	}
}

// The pinned port's generation must survive a controller restart: falling back to
// generation 0 would hand the exit back a tuple the path may have poisoned.
func TestAWGPortRotationPersists(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	gen, at, err := st.GetAWGPortRotation(ctx, "master-xa-1", "exit-a")
	if err != nil || gen != 0 || !at.IsZero() {
		t.Fatalf("unrotated exit: gen=%d at=%v err=%v", gen, at, err)
	}
	when := time.Unix(1_800_000_000, 0).UTC()
	if err := st.SetAWGPortRotation(ctx, "master-xa-1", "exit-a", 2, when); err != nil {
		t.Fatal(err)
	}
	gen, at, err = st.GetAWGPortRotation(ctx, "master-xa-1", "exit-a")
	if err != nil || gen != 2 || !at.Equal(when) {
		t.Fatalf("after rotation: gen=%d at=%v err=%v", gen, at, err)
	}
}

func TestAWGPortRotationIsPerMasterAndExit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0).UTC()
	if err := s.SetAWGPortRotation(ctx, "master-xa-1", "exit-de-1", 3, at); err != nil {
		t.Fatal(err)
	}
	if gen, _, err := s.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1"); err != nil || gen != 0 {
		t.Errorf("another master's generation = %d, %v; want 0 (its own tunnel never rotated)", gen, err)
	}
	gen, rotated, err := s.GetAWGPortRotation(ctx, "master-xa-1", "exit-de-1")
	if err != nil || gen != 3 || !rotated.Equal(at) {
		t.Errorf("got gen=%d at=%v err=%v", gen, rotated, err)
	}
	if err := s.SetAWGPortRotation(ctx, "", "exit-de-1", 1, at); err == nil {
		t.Error("a rotation without a master must be refused")
	}
}

// The generations recorded before tunnels were keyed by master belong to the one
// master there was. Starting them again at 0 would hand an exit back the port a
// path filter already poisoned.
func TestAdoptAWGPortRotationKeepsThePoisonedPortRetired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0).UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO awg_port_rotation (node_id, generation, rotated_at) VALUES ('exit-de-1', 4, ?)`,
		fmtTime(at)); err != nil {
		t.Fatal(err)
	}
	n, err := s.AdoptAWGPortRotation(ctx, "master-xa-1")
	if err != nil || n != 1 {
		t.Fatalf("adopted %d, %v; want 1", n, err)
	}
	if gen, _, _ := s.GetAWGPortRotation(ctx, "master-xa-1", "exit-de-1"); gen != 4 {
		t.Errorf("generation after adoption = %d, want 4", gen)
	}
	// One-shot: a later run with another master must not hand it the same history.
	if n, err := s.AdoptAWGPortRotation(ctx, "master-xa-2"); err != nil || n != 0 {
		t.Errorf("second adoption = %d, %v; want 0", n, err)
	}
	if gen, _, _ := s.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1"); gen != 0 {
		t.Errorf("a second master inherited generation %d", gen)
	}
}

// Every report overwrites the last: a peer list that outlived the report it came
// from would be read as live handshakes, and a frozen handshake reads as a dead
// tunnel.
func TestStatusMasterPeersFollowTheLatestReport(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	node := sampleNode()
	if err := s.UpsertNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	peers := []domain.MasterPeerStatus{{PublicKey: "keyA", Endpoint: "203.0.113.1:23456", LastHandshake: time.Unix(1_800_000_000, 0).UTC()}}
	if err := s.RecordStatus(ctx, domain.NodeStatus{NodeID: node.ID, State: domain.StateReady, MasterPeers: peers}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetStatus(ctx, node.ID)
	if err != nil || len(got.MasterPeers) != 1 || got.MasterPeers[0].Endpoint != "203.0.113.1:23456" {
		t.Fatalf("stored peers = %+v, %v", got.MasterPeers, err)
	}
	if err := s.RecordStatus(ctx, domain.NodeStatus{NodeID: node.ID, State: domain.StateReady}); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetStatus(ctx, node.ID)
	if err != nil || len(got.MasterPeers) != 0 {
		t.Errorf("peers after a report without any = %+v, %v; want none", got.MasterPeers, err)
	}
}

// The address an exit confirmed for one master, the peer the confirmation is
// about and the moment it was earned must survive a controller restart: a gate
// that forgets it has the master speak first on a filtered path.
func TestAWGPinConfirmationPersistsPerMasterAndExit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	addr, key, since, err := s.GetAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1")
	if err != nil || addr != "" || key != "" || !since.IsZero() {
		t.Fatalf("unconfirmed tunnel: addr=%q key=%q since=%v err=%v; want zero values", addr, key, since, err)
	}
	at := time.Unix(1_800_000_000, 0).UTC()
	if err := s.SetAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1", "203.0.113.1:40001", "key-a", at); err != nil {
		t.Fatal(err)
	}
	addr, key, since, err = s.GetAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1")
	if err != nil || addr != "203.0.113.1:40001" || key != "key-a" || !since.Equal(at) {
		t.Errorf("got addr=%q key=%q since=%v err=%v", addr, key, since, err)
	}
	if addr, _, _, err := s.GetAWGPinConfirmation(ctx, "master-xa-2", "exit-de-1"); err != nil || addr != "" {
		t.Errorf("another master's confirmation = %q, %v; want none", addr, err)
	}
	// A later confirmation replaces the earlier one whole.
	later := at.Add(time.Hour)
	if err := s.SetAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1", "203.0.113.1:40002", "", later); err != nil {
		t.Fatal(err)
	}
	addr, key, since, err = s.GetAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1")
	if err != nil || addr != "203.0.113.1:40002" || key != "" || !since.Equal(later) {
		t.Errorf("after replacing: addr=%q key=%q since=%v err=%v", addr, key, since, err)
	}
	if err := s.SetAWGPinConfirmation(ctx, "", "exit-de-1", "203.0.113.1:40001", "key-a", at); err == nil {
		t.Error("a confirmation without a master must be refused")
	}
	// Forgotten reads exactly like never confirmed, and forgetting twice is fine.
	for i := 0; i < 2; i++ {
		if err := s.DeleteAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1"); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	addr, key, since, err = s.GetAWGPinConfirmation(ctx, "master-xa-1", "exit-de-1")
	if err != nil || addr != "" || key != "" || !since.IsZero() {
		t.Errorf("after forgetting: addr=%q key=%q since=%v err=%v; want zero values", addr, key, since, err)
	}
}

// Deleting a node takes what was confirmed for it, as master or as exit — and
// leaves the port generations, which retire ports a path already poisoned.
func TestDeleteNodeForgetsItsPinConfirmations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	at := time.Unix(1_800_000_000, 0).UTC()
	for _, id := range []string{"master-xa-1", "master-xa-2", "exit-de-1", "exit-de-2"} {
		if err := s.UpsertNode(ctx, domain.Node{ID: id, Name: id, Role: domain.RoleExit, State: domain.StateReady}); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []string{"master-xa-1", "master-xa-2"} {
		for _, e := range []string{"exit-de-1", "exit-de-2"} {
			if err := s.SetAWGPinConfirmation(ctx, m, e, "203.0.113.1:40001", "key", at); err != nil {
				t.Fatal(err)
			}
			if err := s.SetAWGPortRotation(ctx, m, e, 3, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	confirmed := func(m, e string) bool {
		addr, _, _, err := s.GetAWGPinConfirmation(ctx, m, e)
		if err != nil {
			t.Fatal(err)
		}
		return addr != ""
	}

	if err := s.DeleteNode(ctx, "master-xa-2"); err != nil {
		t.Fatal(err)
	}
	if confirmed("master-xa-2", "exit-de-1") || confirmed("master-xa-2", "exit-de-2") {
		t.Error("the deleted master's confirmations survived it")
	}
	if !confirmed("master-xa-1", "exit-de-1") || !confirmed("master-xa-1", "exit-de-2") {
		t.Error("another master's confirmations were deleted with it")
	}
	if err := s.DeleteNode(ctx, "exit-de-2"); err != nil {
		t.Fatal(err)
	}
	if confirmed("master-xa-1", "exit-de-2") {
		t.Error("the confirmation for a deleted exit survived it")
	}
	if !confirmed("master-xa-1", "exit-de-1") {
		t.Error("the confirmation for another exit was deleted with it")
	}
	if gen, _, _ := s.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1"); gen != 3 {
		t.Errorf("port generation after the delete = %d, want 3 kept: generation 0 is a port already judged poisoned", gen)
	}
}

func TestAutoSuspendedRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	got, err := st.ListAutoSuspended(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty store: %v, %v", got, err)
	}
	since := time.Date(2026, 10, 9, 18, 0, 0, 0, time.UTC)
	if err := st.SetAutoSuspended(ctx, "exit-a", since); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAutoSuspended(ctx, "exit-a", since.Add(time.Minute)); err != nil { // replaces
		t.Fatal(err)
	}
	if err := st.SetAutoSuspended(ctx, "exit-b", since); err != nil {
		t.Fatal(err)
	}
	got, err = st.ListAutoSuspended(ctx)
	if err != nil || len(got) != 2 || !got["exit-a"].Equal(since.Add(time.Minute)) || !got["exit-b"].Equal(since) {
		t.Fatalf("list = %v, %v", got, err)
	}
	if err := st.ClearAutoSuspended(ctx, "exit-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearAutoSuspended(ctx, "exit-a"); err != nil { // absent ⇒ no-op
		t.Fatal(err)
	}
	got, _ = st.ListAutoSuspended(ctx)
	if _, still := got["exit-a"]; still || len(got) != 1 {
		t.Fatalf("after clear: %v", got)
	}
	if err := st.SetAutoSuspended(ctx, "", since); err == nil {
		t.Fatal("an empty exit name was accepted")
	}
}

// The suspension is about the node that was there: deleting the node drops it,
// and a node with none is deleted like any other.
func TestDeleteNodeForgetsItsAutoSuspension(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	since := time.Unix(1_800_000_000, 0).UTC()
	for _, id := range []string{"exit-de-1", "exit-de-2", "exit-de-3"} {
		if err := s.UpsertNode(ctx, domain.Node{ID: id, Name: id, Role: domain.RoleExit, State: domain.StateReady}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"exit-de-1", "exit-de-2"} {
		if err := s.SetAutoSuspended(ctx, id, since); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"exit-de-1", "exit-de-3"} {
		if err := s.DeleteNode(ctx, id); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}
	got, err := s.ListAutoSuspended(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := got["exit-de-2"]; !kept || len(got) != 1 {
		t.Fatalf("after deleting exit-de-1 and exit-de-3: %v, want only exit-de-2", got)
	}
}

// The whole point of the table: it is still there after the process is gone.
func TestAutoSuspendedSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	since := time.Date(2026, 10, 9, 18, 33, 38, 461576765, time.UTC)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAutoSuspended(ctx, "exit-a", since); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	got, err := st.ListAutoSuspended(ctx)
	if err != nil || len(got) != 1 || !got["exit-a"].Equal(since) {
		t.Fatalf("after reopen: %v, %v", got, err)
	}
}
