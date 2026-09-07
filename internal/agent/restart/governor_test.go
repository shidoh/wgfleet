package restart

import (
	"testing"
	"time"
)

// clk is a controllable clock so the policy can be exercised without sleeping.
type clk struct{ t time.Time }

func (c *clk) now() time.Time      { return c.t }
func (c *clk) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestGovernor() (*Governor, *clk) {
	c := &clk{t: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}
	g := New(nil)
	g.now = c.now
	return g, c
}

// TestFreeBudgetRestartsImmediately — the common case is a single transient crash,
// and one restart usually fixes it. Throttling that would turn a 30-second blip
// into minutes of downtime, so the first few restarts must be free.
func TestFreeBudgetRestartsImmediately(t *testing.T) {
	g, c := newTestGovernor()
	for i := 0; i < FreeBudget; i++ {
		if ok, _ := g.Allow("mihomo"); !ok {
			t.Fatalf("restart %d of the free budget was suppressed", i+1)
		}
		g.Record("mihomo")
		c.add(30 * time.Second) // one reconcile tick
	}
}

// TestBudgetExhaustionStartsBackoff is the crash-loop guard: past the free budget
// the restarts must stop being free, or a service that dies instantly on start is
// respawned twice a minute forever.
func TestBudgetExhaustionStartsBackoff(t *testing.T) {
	g, c := newTestGovernor()
	for i := 0; i < FreeBudget; i++ {
		if i > 0 {
			c.add(30 * time.Second) // one reconcile tick between restarts
		}
		g.Record("mihomo")
	}
	ok, until := g.Allow("mihomo")
	if ok {
		t.Fatal("the restart past the free budget must be suppressed")
	}
	if got := until.Sub(c.now()); got != BackoffBase {
		t.Errorf("first pause = %v, want %v", got, BackoffBase)
	}
}

// TestBackoffDoublesAndCaps — each over-budget attempt doubles the pause, bounded
// so a persistently broken service still retries a few times an hour and can
// self-heal when the cause disappears (memory freed, network back).
func TestBackoffDoublesAndCaps(t *testing.T) {
	g, _ := newTestGovernor()
	for i := 0; i < FreeBudget; i++ {
		g.Record("mihomo") // spend the budget
	}
	// Each further restart doubles the pause until it saturates. Record models the
	// event "a restart happened"; the ladder is what is under test here, so the
	// clock is left still to keep the crash window out of it.
	want := []time.Duration{BackoffBase, 2 * BackoffBase, 4 * BackoffBase, 8 * BackoffBase, BackoffCap, BackoffCap}
	for i, w := range want {
		ok, until := g.Allow("mihomo")
		if ok {
			t.Fatalf("attempt %d must be suppressed", i)
		}
		if got := until.Sub(g.now()); got != w {
			t.Fatalf("attempt %d pause = %v, want %v", i, got, w)
		}
		g.Record("mihomo")
	}
	if _, until := g.Allow("mihomo"); until.Sub(g.now()) > BackoffCap {
		t.Errorf("pause exceeded the cap %v", BackoffCap)
	}
}

// TestHealthyRunResetsTheBudget — a service that ran fine for a long stretch and
// then died is not in a crash loop; it gets the full free budget again. Without
// this an unrelated crash hours later would inherit a punitive pause.
func TestHealthyRunResetsTheBudget(t *testing.T) {
	g, c := newTestGovernor()
	for i := 0; i < FreeBudget; i++ {
		g.Record("mihomo")
		c.add(time.Second)
	}
	if ok, _ := g.Allow("mihomo"); ok {
		t.Fatal("precondition: budget should be exhausted")
	}
	c.add(HealthyRun + time.Second)
	if ok, _ := g.Allow("mihomo"); !ok {
		t.Error("a restart after a healthy run must be free again")
	}
}

// TestWindowSlides — the budget applies to a sliding window, so restarts spread
// thinly over hours never accumulate into a false crash loop.
func TestWindowSlides(t *testing.T) {
	g, c := newTestGovernor()
	for i := 0; i < FreeBudget*3; i++ {
		if ok, _ := g.Allow("blocky"); !ok {
			t.Fatalf("restart %d spread beyond the window must not be suppressed", i)
		}
		g.Record("blocky")
		c.add(CrashWindow / 2) // far enough apart that at most one stays in window
	}
}

// TestKeysAreIndependent — a crash-looping blocky must not suppress a legitimate
// mihomo restart. They are separate services with separate failure modes.
func TestKeysAreIndependent(t *testing.T) {
	g, c := newTestGovernor()
	for i := 0; i < FreeBudget; i++ {
		g.Record("blocky")
		c.add(time.Second)
	}
	if ok, _ := g.Allow("blocky"); ok {
		t.Fatal("precondition: blocky budget should be exhausted")
	}
	if ok, _ := g.Allow("mihomo"); !ok {
		t.Error("mihomo must be unaffected by blocky's crash loop")
	}
}

// TestZeroValueGovernorAllows — a nil/unset governor must never block a restart.
// Every planner takes it optionally, and "not wired up" has to mean "behave as
// before", never "silently stop self-healing".
func TestZeroValueGovernorAllows(t *testing.T) {
	var g *Governor
	if ok, _ := g.Allow("mihomo"); !ok {
		t.Error("a nil governor must allow every restart")
	}
	g.Record("mihomo") // must not panic
}

// TestSnapshotExposesTotalsAndThrottle — the governor is the only thing that knows
// how often a service has needed a self-heal restart, and whether it has given up
// restarting it. Both facts were invisible: a throttled service is the SAME defect
// as a restart loop with the symptom muted, and a metric that only saw restarts
// would read the throttle as recovery.
func TestSnapshotExposesTotalsAndThrottle(t *testing.T) {
	g, c := newTestGovernor()
	if snap := g.Snapshot(); len(snap) != 0 {
		t.Fatalf("fresh governor must know no services, got %v", snap)
	}
	g.Record("mihomo")
	st := g.Snapshot()["mihomo"]
	if st.Restarts != 1 || st.Throttled {
		t.Fatalf("after one restart: want {1 false}, got %+v", st)
	}
	for i := 1; i < FreeBudget; i++ {
		c.add(30 * time.Second)
		g.Record("mihomo")
	}
	st = g.Snapshot()["mihomo"]
	if st.Restarts != FreeBudget || !st.Throttled {
		t.Fatalf("budget spent: want {%d true}, got %+v", FreeBudget, st)
	}
	// Totals are monotonic: the healthy-run reset forgets the window, not history.
	c.add(HealthyRun + time.Minute)
	st = g.Snapshot()["mihomo"]
	if st.Restarts != FreeBudget || st.Throttled {
		t.Fatalf("after a healthy run: want {%d false}, got %+v", FreeBudget, st)
	}
	var nilGov *Governor
	if snap := nilGov.Snapshot(); snap != nil {
		t.Errorf("nil governor must report nothing, got %v", snap)
	}
}
