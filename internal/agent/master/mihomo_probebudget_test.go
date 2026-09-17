package master

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The probing phase shares one deadline across every member. When it expires,
// cancelling it takes the in-flight HTTP requests down with it — and
// `GET /proxies/{name}/delay` is not a read: adapter.Proxy.URLTest stores
// `alive = (err == nil)` in a defer, for every call, including an abandoned one.
// So a phase that runs out of budget marks whatever it was probing DEAD inside
// mihomo, while the agent reads the same sample as "untrustworthy" and holds its
// own verdict — no log line, no metric, no alert.
//
// Under consistent-hashing that is a data-plane outage: every destination pinned
// to an evicted exit fails until the group's own 30s check puts it back. Observed
// live on 2026-09-05, when all three carrying exits were judged unreachable within
// FOUR MILLISECONDS of each other — three independent network paths cannot fail
// that way, so the verdict was a property of the prober, not of the exits.
//
// The bound on the phase is not the problem; abandoning a request to enforce it is.
// A member we have no time for must be left UNPROBED, never probed-and-cancelled.
func TestProbingPhaseNeverAbandonsAnInFlightProbe(t *testing.T) {
	var abandoned, received atomic.Int32

	// A Clash API that answers, but not instantly — the window in which the phase
	// deadline can catch a request mid-flight, which is the whole point here.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		select {
		case <-time.After(150 * time.Millisecond):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"delay":42}`))
		case <-r.Context().Done():
			// The client went away before we answered. This is exactly the call that
			// makes mihomo write alive=false on a proxy nobody judged unhealthy.
			abandoned.Add(1)
		}
	}))
	defer srv.Close()

	p := mihomoPlanner{
		paths:      PathsUnder(t.TempDir()),
		privateKey: "k",
		tier:       NewTierSelector(nil),
		// Smaller than one handler round: the phase is guaranteed to run out of
		// budget while a probe is on the wire.
		probeBudget: 100 * time.Millisecond,
		// Room for an attempt that has already started to finish on its own terms.
		probeAttempt: 2 * time.Second,
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		BindAddress:        "10.80.0.1",
		ExternalController: srv.Listener.Addr().String(),
		ExitTunnels: []domain.ExitTunnel{
			{Name: "e1", Endpoint: "203.0.113.1:51820", ServerPublicKey: "k1", TunnelIP: "10.81.0.2", MTU: 1360},
			{Name: "e2", Endpoint: "203.0.113.2:51820", ServerPublicKey: "k2", TunnelIP: "10.82.0.2", MTU: 1360},
			{Name: "e3", Endpoint: "203.0.113.3:51820", ServerPublicKey: "k3", TunnelIP: "10.83.0.2", MTU: 1360, Reserve: true},
		},
	}}

	if _, err := p.Plan(context.Background(), spec); err != nil {
		t.Fatalf("Plan() = %v", err)
	}

	// Without this the test passes when nothing was probed at all, which is how a
	// test that cannot fail looks: a phase that probes nobody abandons nobody.
	// Counted on ARRIVAL, not on a successful answer — an abandoned request is
	// exactly the case this test is about, and it never reaches an answer.
	if received.Load() == 0 {
		t.Fatal("the Clash API saw no probe at all — the phase did not run, so this proves nothing")
	}
	if got := abandoned.Load(); got != 0 {
		t.Errorf("%d probe(s) abandoned mid-flight; each one writes alive=false on an exit "+
			"nobody judged unhealthy. A member the budget cannot cover must be left unprobed.", got)
	}
}

// Skipping a member for lack of budget must produce NO VERDICT about it, not a bad
// one. "We had no time to ask" and "it answered nothing" are the same shape — both
// end with zero destinations reached — and collapsing them would hold an exit out
// because the clock ran out rather than because anything is wrong with it.
//
// This is NOT a regression test for the mid-flight cancellation that motivated
// budgetedProbe — that bug lived in mihomo's own alive flag, which TierSelector
// cannot see, and the old code passed this scenario too (a cancelled probe already
// surfaced as a transport error, which tierUsable already treated as blind).
// TestProbingPhaseNeverAbandonsAnInFlightProbe is the test that guards the incident.
//
// What this one pins is the NEW boundary the fix introduced: the skip path must
// report an error, never a clean 0-of-0 result. The tier selector does the right
// thing with a sample it is TOLD is blind (tierUsable: "neither hold nor release on
// a sample we cannot trust"); it has no way to recognise a silent one.
func TestBudgetExhaustionHoldsNoExitOut(t *testing.T) {
	// A Clash API that answers "I dialed and failed" (mihomo reports delay 0), slowly
	// enough that the one permitted attempt eats the whole budget. The first member
	// must FAIL for this test to mean anything: tierUsable stops walking at the first
	// member it can prove usable, so a healthy first member would leave the rest
	// unvisited and the skip path untested.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(120 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"delay":0}`))
	}))
	defer srv.Close()

	tier := NewTierSelector(nil)
	p := mihomoPlanner{
		paths:        PathsUnder(t.TempDir()),
		privateKey:   "k",
		tier:         tier,
		probeBudget:  100 * time.Millisecond,
		probeAttempt: 2 * time.Second,
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		BindAddress:        "10.80.0.1",
		ExternalController: srv.Listener.Addr().String(),
		// A reserve member is required, not decoration: with an empty reserve tier
		// there is nowhere to fail over to, so ReserveActive decides without probing
		// anyone and the phase this test is about never runs.
		ExitTunnels: []domain.ExitTunnel{
			{Name: "e1", Endpoint: "203.0.113.1:51820", ServerPublicKey: "k1", TunnelIP: "10.81.0.2", MTU: 1360},
			{Name: "e2", Endpoint: "203.0.113.2:51820", ServerPublicKey: "k2", TunnelIP: "10.82.0.2", MTU: 1360},
			{Name: "e3", Endpoint: "203.0.113.3:51820", ServerPublicKey: "k3", TunnelIP: "10.83.0.2", MTU: 1360, Reserve: true},
		},
	}}

	if _, err := p.Plan(context.Background(), spec); err != nil {
		t.Fatalf("Plan() = %v", err)
	}

	// Which member goes first is the walk's business (tierUsable rotates the starting
	// point by pass number), so the assertion counts verdicts instead of naming them.
	// The budget covers exactly ONE attempt, so exactly one member can have been
	// judged — the second is the one nobody had time to ask.
	rotation := tier.Rotation()
	held := 0
	for _, out := range rotation {
		if out {
			held++
		}
	}
	if held == 0 {
		t.Fatalf("nothing was held out (rotation=%v) — the probed member was never judged, "+
			"so the skipped one proves nothing", rotation)
	}
	if held > 1 {
		t.Errorf("%d exits held out (rotation=%v), but the budget covered one probe; the extra "+
			"verdict came from a member nobody asked — a skipped sample must be blind, not failing",
			held, rotation)
	}
}
