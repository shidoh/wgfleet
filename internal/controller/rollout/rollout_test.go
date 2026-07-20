package rollout

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// fakeClock drives the gate on virtual time: sleep advances the clock instead of
// blocking, so a 3-minute confirm timeout costs a test nothing and never flakes.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func (f *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.advance(d)
	return nil
}

// fakeUpgrader records the SSH-side calls and can fail a chosen node.
type fakeUpgrader struct {
	mu         sync.Mutex
	installed  string
	failOn     map[string]error
	rollbackEr map[string]error
	upgraded   []string
	rolledBack []string
}

func newUpgrader(installed string) *fakeUpgrader {
	return &fakeUpgrader{
		installed:  installed,
		failOn:     map[string]error{},
		rollbackEr: map[string]error{},
	}
}

func (f *fakeUpgrader) UpgradeAgentVerified(_ context.Context, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upgraded = append(f.upgraded, id)
	if err := f.failOn[id]; err != nil {
		return "", err
	}
	return f.installed, nil
}

func (f *fakeUpgrader) RollbackAgent(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rolledBack = append(f.rolledBack, id)
	return f.rollbackEr[id]
}

func (f *fakeUpgrader) touched() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.upgraded...)
}

func (f *fakeUpgrader) restored() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.rolledBack...)
}

// fakeStore returns node rows from a per-node function of the read count, so a
// test can make a node come back after N polls, or never.
type fakeStore struct {
	mu    sync.Mutex
	clock *fakeClock
	fn    func(id string, call int) domain.Node
	calls map[string]int
}

func (s *fakeStore) GetNode(_ context.Context, id string) (domain.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[id]++
	return s.fn(id, s.calls[id]), nil
}

func testCoordinator(up Upgrader, read NodeReader, clk *fakeClock) *Coordinator {
	// LockPath "-" disables the cross-process flock: these tests exercise the
	// coordinator's logic, not fleet-wide exclusion (see lock_test.go for that),
	// and they must not contend on a real lock file or need /var/lib.
	c := New(up, read, Config{LockPath: "-"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = clk.now
	c.sleep = clk.sleep
	return c
}

func planOf(names ...string) Plan {
	p := Plan{Want: "new"}
	for _, n := range names {
		p.Targets = append(p.Targets, Target{NodeID: n, Name: n, Tier: TierPrimary})
	}
	return p
}

func phases(s State) map[string]Phase {
	out := map[string]Phase{}
	for _, n := range s.Nodes {
		out[n.Name] = n.Phase
	}
	return out
}

// --- the gate ---------------------------------------------------------------

func TestGateReasonRequiresReadyVersionAndFreshness(t *testing.T) {
	clk := newClock()
	c := testCoordinator(newUpgrader("new"), nil, clk)
	restarted := clk.now()
	fresh := restarted.Add(time.Second)

	tests := []struct {
		name string
		node domain.Node
		// elapsed is how far the clock has moved past the node's LastSeen when the
		// gate is evaluated — the freshness dimension.
		elapsed time.Duration
		wantOK  bool
	}{
		{
			name:   "ready, right version, reported after the restart",
			node:   domain.Node{State: domain.StateReady, AgentVersion: "new", LastSeen: fresh},
			wantOK: true,
		},
		{
			name:   "degraded blocks even on the right version",
			node:   domain.Node{State: domain.StateDegraded, AgentVersion: "new", LastSeen: fresh},
			wantOK: false,
		},
		{
			name:   "still reporting the old version blocks",
			node:   domain.Node{State: domain.StateReady, AgentVersion: "old", LastSeen: fresh},
			wantOK: false,
		},
		{
			name:   "last report predates the restart, so it is the old process",
			node:   domain.Node{State: domain.StateReady, AgentVersion: "new", LastSeen: restarted.Add(-time.Minute)},
			wantOK: false,
		},
		{
			name:    "reported after the restart but long since gone silent",
			node:    domain.Node{State: domain.StateReady, AgentVersion: "new", LastSeen: fresh},
			elapsed: defaultFreshWithin + time.Minute,
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk2 := newClock()
			clk2.advance(tc.elapsed)
			c.now = clk2.now
			reason := c.gateReason(tc.node, "new", restarted)
			if gotOK := reason == ""; gotOK != tc.wantOK {
				t.Fatalf("gateReason = %q (ok=%v), want ok=%v", reason, gotOK, tc.wantOK)
			}
		})
	}
}

func TestRolloutAdvancesOnlyAfterTheNodeConfirms(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	// anz3 stays Degraded for two polls, then comes back correctly.
	st := &fakeStore{clock: clk, fn: func(id string, call int) domain.Node {
		if id == "anz3" && call <= 2 {
			return domain.Node{State: domain.StateDegraded, AgentVersion: "old", LastSeen: clk.now()}
		}
		return domain.Node{State: domain.StateReady, AgentVersion: "new", LastSeen: clk.now()}
	}}
	c := testCoordinator(up, st, clk)

	if err := c.Start(context.Background(), planOf("anz3", "vn1")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.Wait()

	got := phases(c.Snapshot())
	if got["anz3"] != PhaseDone || got["vn1"] != PhaseDone {
		t.Fatalf("phases = %v, want both done", got)
	}
	if want := []string{"anz3", "vn1"}; !eq(up.touched(), want) {
		t.Fatalf("upgraded %v, want %v (in order)", up.touched(), want)
	}
	if len(up.restored()) != 0 {
		t.Errorf("unexpected rollback: %v", up.restored())
	}
}

// --- timeout → rollback -----------------------------------------------------

func TestNodeThatNeverComesBackIsRolledBack(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	// The signature of the real incident: the service is restarted but the new
	// binary crash-loops, so the node never reports on the new version.
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node {
		return domain.Node{State: domain.StateDegraded, AgentVersion: "old", LastSeen: clk.now()}
	}}
	c := testCoordinator(up, st, clk)

	if err := c.Start(context.Background(), planOf("anz3", "vn1")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.Wait()

	s := c.Snapshot()
	if got := phases(s)["anz3"]; got != PhaseRolledBack {
		t.Fatalf("anz3 phase = %q, want %q", got, PhaseRolledBack)
	}
	if !eq(up.restored(), []string{"anz3"}) {
		t.Fatalf("rolled back %v, want [anz3]", up.restored())
	}
	if !s.Nodes[0].RolledBack || s.Nodes[0].Err == "" {
		t.Errorf("rollback not recorded with a reason: %+v", s.Nodes[0])
	}
}

func TestRollbackFailureIsSurfacedNotSwallowed(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	up.failOn["anz3"] = errors.New("sha256 mismatch")
	up.rollbackEr["anz3"] = errors.New("ssh unreachable")
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node { return domain.Node{} }}
	c := testCoordinator(up, st, clk)

	_ = c.Start(context.Background(), planOf("anz3"))
	c.Wait()

	s := c.Snapshot()
	if s.Nodes[0].Phase != PhaseFailed {
		t.Fatalf("phase = %q, want %q", s.Nodes[0].Phase, PhaseFailed)
	}
	if got := s.Nodes[0].Err; got == "" || !contains(got, "ROLLBACK ALSO FAILED") {
		t.Fatalf("node error %q does not report the failed rollback", got)
	}
}

// --- abort on first failure -------------------------------------------------

func TestFirstFailureLeavesEveryLaterNodeUntouched(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	up.failOn["anz3"] = errors.New("binary corrupt")
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node { return domain.Node{} }}
	c := testCoordinator(up, st, clk)

	// anz3 is first (reserve tier in a real plan); vn1 and vn2 must never be dialled.
	if err := c.Start(context.Background(), planOf("anz3", "vn1", "vn2")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.Wait()

	if !eq(up.touched(), []string{"anz3"}) {
		t.Fatalf("upgraded %v — the rollout must stop at the first failure", up.touched())
	}
	got := phases(c.Snapshot())
	if got["anz3"] != PhaseRolledBack {
		t.Errorf("anz3 = %q, want %q", got["anz3"], PhaseRolledBack)
	}
	for _, n := range []string{"vn1", "vn2"} {
		if got[n] != PhaseSkipped {
			t.Errorf("%s = %q, want %q", n, got[n], PhaseSkipped)
		}
	}
	if s := c.Snapshot(); s.Err == "" {
		t.Error("rollout state carries no halt reason")
	}
}

// --- concurrency ------------------------------------------------------------

func TestSecondRolloutIsRefusedWhileOneRuns(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	release := make(chan struct{})
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node {
		<-release // hold the first rollout inside its confirm gate
		return domain.Node{State: domain.StateReady, AgentVersion: "new", LastSeen: clk.now()}
	}}
	c := testCoordinator(up, st, clk)

	if err := c.Start(context.Background(), planOf("anz3")); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := c.Start(context.Background(), planOf("vn1")); !errors.Is(err, ErrBusy) {
		t.Fatalf("second Start error = %v, want ErrBusy", err)
	}
	close(release)
	c.Wait()

	if err := c.Start(context.Background(), planOf("vn1")); err != nil {
		t.Fatalf("Start after completion: %v", err)
	}
	c.Wait()
}

func TestStartRejectsAnEmptyPlan(t *testing.T) {
	c := testCoordinator(newUpgrader("new"), nil, newClock())
	if err := c.Start(context.Background(), Plan{}); err == nil {
		t.Fatal("expected an error for a plan with no targets")
	}
}

// --- shutdown / abort -------------------------------------------------------

func TestCancelledContextStopsTheRolloutAndRollsBackTheNodeInFlight(t *testing.T) {
	clk := newClock()
	up := newUpgrader("new")
	ctx, cancel := context.WithCancel(context.Background())
	st := &fakeStore{clock: clk, fn: func(string, int) domain.Node {
		cancel() // the controller shuts down while anz3 is being confirmed
		return domain.Node{State: domain.StateDegraded, LastSeen: clk.now()}
	}}
	c := testCoordinator(up, st, clk)

	if err := c.Start(ctx, planOf("anz3", "vn1")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	c.Wait()

	if !eq(up.touched(), []string{"anz3"}) {
		t.Fatalf("upgraded %v, want only anz3", up.touched())
	}
	// The rollback must still run even though the rollout's context is cancelled —
	// otherwise shutdown strands the node on an unconfirmed binary.
	if !eq(up.restored(), []string{"anz3"}) {
		t.Fatalf("rolled back %v, want [anz3]", up.restored())
	}
	if got := phases(c.Snapshot())["vn1"]; got != PhaseSkipped {
		t.Errorf("vn1 = %q, want %q", got, PhaseSkipped)
	}
	if c.Running() {
		t.Error("coordinator still reports a running rollout after cancellation")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
