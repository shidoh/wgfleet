package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/rollout"
)

// fakeRoller is a scriptable Roller for the handler/template tests.
type fakeRoller struct {
	mu       sync.Mutex
	plan     rollout.Plan
	state    rollout.State
	startErr error
	starts   int
	aborts   int
}

func (f *fakeRoller) Plan() rollout.Plan { return f.plan }

func (f *fakeRoller) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	return f.startErr
}

func (f *fakeRoller) Abort() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aborts++
}

func (f *fakeRoller) Snapshot() rollout.State { return f.state }

func (f *fakeRoller) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.aborts
}

func rollerHandler(t *testing.T, r Roller) *Handler {
	t.Helper()
	h, err := New(nil, nil, nil, nil, nil, nil, 0)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	h.SetRoller(r)
	return h
}

// rawPost posts a form with a caller-chosen CSRF token. Unlike the shared
// postForm helper it does NOT sign the request, which is the point: these tests
// assert the guard rejects a bad token as well as accepting a good one.
func rawPost(h *Handler, path, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("csrf_token="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	return w
}

// TestRolloutPlanHiddenWhileAFinishedRunIsOnScreen pins the panel to ONE list of
// nodes. State.Nodes is not cleared when a run ends (only Active flips), and Plan
// is recomputed live — so a finished run plus a still-outdated plan rendered the
// same nodes twice: once with phases and versions, once again under PLANNED ORDER
// without them. The window is not momentary: it lasts until every agent
// re-reports its new version, and never closes at all if a node was skipped,
// failed, or stopped reporting.
//
// Skipped nodes are the exception and must survive: they are never in State.Nodes,
// so hiding them with the plan would drop the only place their reason is shown.
func TestRolloutPlanHiddenWhileAFinishedRunIsOnScreen(t *testing.T) {
	r := &fakeRoller{
		plan: rollout.Plan{
			Want: "new-build",
			Targets: []rollout.Target{
				{NodeID: "anz3", Name: "anz3", Tier: rollout.TierReserve, Current: "june"},
				{NodeID: "vn1", Name: "vn1", Tier: rollout.TierPrimary, Current: "june"},
			},
			Skipped: []rollout.Skipped{{Name: "old", Reason: "no ssh target in the manifest"}},
		},
		state: rollout.State{
			Active: false,
			Nodes: []rollout.NodeProgress{
				{Target: rollout.Target{Name: "anz3", Tier: rollout.TierReserve}, Phase: rollout.PhaseDone, Installed: "new-build"},
				{Target: rollout.Target{Name: "vn1", Tier: rollout.TierPrimary}, Phase: rollout.PhaseDone, Installed: "new-build"},
			},
		},
	}
	h := rollerHandler(t, r)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/partials/rollout", nil))
	body := w.Body.String()

	if strings.Contains(body, "PLANNED ORDER") {
		t.Error("PLANNED ORDER renders under a finished run — the same nodes are listed twice")
	}
	if n := strings.Count(body, `class="roll-planrow"`); n != 0 {
		t.Errorf("%d plan rows render under a finished run, want 0", n)
	}
	// What must still be there: the finished run itself, the way to roll again,
	// and the skipped node's reason.
	if n := strings.Count(body, `class="roll-row`); n != 2 {
		t.Errorf("finished-run progress rows = %d, want 2", n)
	}
	if !strings.Contains(body, "Update 2 outdated exits") {
		t.Error("the start button must remain — the plan list is redundant, the action is not")
	}
	if !strings.Contains(body, "no ssh target in the manifest") {
		t.Error("skipped nodes are never in the progress list, so their reason must survive")
	}
}

func TestRolloutPartialRendersPlannedOrder(t *testing.T) {
	r := &fakeRoller{plan: rollout.Plan{
		Want: "new-build",
		Targets: []rollout.Target{
			{NodeID: "anz3", Name: "anz3", Tier: rollout.TierReserve, Current: "june"},
			{NodeID: "vn1", Name: "vn1", Tier: rollout.TierPrimary, Current: "june"},
		},
		Skipped: []rollout.Skipped{{Name: "old", Reason: "no ssh target in the manifest"}},
	}}
	h := rollerHandler(t, r)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/partials/rollout", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("template failed to render: %s", body)
	}
	for _, want := range []string{
		"Update 2 outdated exits", // the action, with the count
		"anz3", "vn1",             // both targets
		"reserve", "primary", // their tiers
		"new-build",                     // the target version
		"no ssh target in the manifest", // the skip reason
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered panel missing %q", want)
		}
	}
	// Reserve must be shown before primary — the panel is how an operator verifies
	// the order before committing.
	if strings.Index(body, "anz3") > strings.Index(body, "vn1") {
		t.Error("planned order renders primary before reserve")
	}
}

func TestRolloutPartialRendersLiveProgressAndAbort(t *testing.T) {
	r := &fakeRoller{
		plan: rollout.Plan{Want: "new-build"},
		state: rollout.State{
			Active: true,
			Nodes: []rollout.NodeProgress{
				{Target: rollout.Target{Name: "anz3", Tier: rollout.TierReserve}, Phase: rollout.PhaseDone, Installed: "new-build"},
				{Target: rollout.Target{Name: "vn1", Tier: rollout.TierPrimary}, Phase: rollout.PhaseConfirming},
				{Target: rollout.Target{Name: "vn2", Tier: rollout.TierPrimary}, Phase: rollout.PhasePending},
			},
		},
	}
	h := rollerHandler(t, r)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/partials/rollout", nil))

	body := w.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("template failed to render: %s", body)
	}
	for _, want := range []string{"Abort rollout", "confirming", "pending", "done", "RUNNING 1/3"} {
		if !strings.Contains(body, want) {
			t.Errorf("live panel missing %q", want)
		}
	}
	if strings.Contains(body, "Update ") {
		t.Error("start action offered while a rollout is running")
	}
}

func TestRolloutPartialShowsNothingToDo(t *testing.T) {
	h := rollerHandler(t, &fakeRoller{plan: rollout.Plan{Want: "new-build"}})
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/partials/rollout", nil))

	if body := w.Body.String(); !strings.Contains(body, "Nothing to roll") {
		t.Errorf("panel does not report an up-to-date fleet: %s", body)
	}
}

// The mutating routes must be CSRF/Sec-Fetch guarded like every other action.
func TestRolloutMutatingRoutesAreGuarded(t *testing.T) {
	tests := []string{"/rollout/start", "/rollout/abort"}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			r := &fakeRoller{plan: rollout.Plan{Targets: []rollout.Target{{Name: "anz3"}}}}
			h := rollerHandler(t, r)

			if w := rawPost(h, path, "wrong-token"); w.Code != http.StatusForbidden {
				t.Fatalf("bad CSRF token: status = %d, want 403", w.Code)
			}
			if starts, aborts := r.counts(); starts != 0 || aborts != 0 {
				t.Fatalf("guard bypassed: starts=%d aborts=%d", starts, aborts)
			}
			if w := rawPost(h, path, h.csrf); w.Code != http.StatusSeeOther {
				t.Fatalf("valid CSRF token: status = %d, want 303", w.Code)
			}
		})
	}
}

// A refused start (already running) must land back on the fleet page as a flash,
// not as a bare error document that replaces the console.
func TestRolloutStartRefusalRedirectsWithFlash(t *testing.T) {
	r := &fakeRoller{startErr: rollout.ErrBusy}
	h := rollerHandler(t, r)

	w := rawPost(h, "/rollout/start", h.csrf)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
	var flash bool
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookie && c.Value != "" {
			flash = true
		}
	}
	if !flash {
		t.Error("no flash cookie set for the refused rollout")
	}
}

// With no Roller wired the action must be absent, not broken.
func TestRolloutEndpointsReportUnconfigured(t *testing.T) {
	h, err := New(nil, nil, nil, nil, nil, nil, 0)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/partials/rollout", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	if h.rolloutView() != nil {
		t.Error("rolloutView returned data with no roller configured")
	}
}

// TestRolloutPanelReportsAnUnidentifiableBinary pins the third state apart from
// "nothing to roll". When the agent binary this controller would push cannot be
// identified, whether any node is outdated is unknowable — rendering the
// all-clear would assert something false, and offering a roll would describe
// work that cannot be named.
func TestRolloutPanelReportsAnUnidentifiableBinary(t *testing.T) {
	r := &fakeRoller{plan: rollout.Plan{Unavailable: `stat agent binary: no such file or directory`}}
	h := rollerHandler(t, r)

	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/partials/rollout", nil))
	body := w.Body.String()

	if !strings.Contains(body, "Cannot determine what would be rolled") {
		t.Error("panel does not surface why no plan could be built")
	}
	if !strings.Contains(body, "no such file or directory") {
		t.Error("panel drops the underlying reason")
	}
	if strings.Contains(body, "Nothing to roll") {
		t.Error("an unidentifiable binary rendered as the all-clear — that is a false claim")
	}
	if strings.Contains(body, "/rollout/start") {
		t.Error("panel offers a roll it cannot describe")
	}
}
