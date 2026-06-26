package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// errInjected is a sentinel returned by stubs to exercise action error paths.
var errInjected = errors.New("injected failure")

type stubRenderer struct {
	spec domain.NodeSpec
	err  error
}

func (s stubRenderer) RenderNodeSpec(context.Context, string) (domain.NodeSpec, error) {
	return s.spec, s.err
}

func (s stubRenderer) ExitTransportInfo(node domain.Node) (domain.MasterTransport, []domain.MasterTransport, bool) {
	if node.Role != domain.RoleExit {
		return "", nil, false
	}
	return s.spec.ActiveTransport.OrDefault(), s.spec.Transports(), true
}

func newTestHandler(t *testing.T, renderer SpecRenderer) (*Handler, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h, err := New(st, renderer, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h, st
}

func seed(t *testing.T, st store.Store, n domain.Node) {
	t.Helper()
	if err := st.UpsertNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, h http.Handler, path string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func TestIndexListsNodesWithStates(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, Region: "de", State: domain.StateReady})
	seed(t, st, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReconciling})

	res, body := get(t, h, "/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	for _, want := range []string{"exit-de-1", "master-xa-1", "wg", "fleet", `badge ready`, `badge reconciling`, "Ready", "Reconciling"} {
		if !strings.Contains(body, want) {
			t.Errorf("index body missing %q", want)
		}
	}
	// htmx live-refresh hook present.
	if !strings.Contains(body, `hx-get="/partials/nodes"`) {
		t.Error("index missing htmx live-refresh hook")
	}
}

func TestIndexEmpty(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	res, body := get(t, h, "/")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "No nodes registered") {
		t.Errorf("expected empty state, got:\n%s", body)
	}
}

func TestNodesPartial(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	res, body := get(t, h, "/partials/nodes")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	// Partial is the table only — no <html> shell.
	if strings.Contains(body, "<html") {
		t.Error("partial should not include the full layout")
	}
	if !strings.Contains(body, "exit-de-1") {
		t.Error("partial missing node")
	}
}

func TestNodeDetailWithStatusAndSpec(t *testing.T) {
	spec := domain.NodeSpec{
		Role:     domain.RoleExit,
		Egress:   domain.EgressWARP,
		WGServer: domain.WGServerSpec{ListenPort: 51820, AddressPool: "10.81.0.0/24", Address: "10.81.0.1", MTU: 1360},
	}
	h, st := newTestHandler(t, stubRenderer{spec: spec})
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, Region: "de", State: domain.StateReady, PublicIP: "198.51.100.7"})
	_ = st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: "exit-de-1", State: domain.StateReady, EgressIP: "104.16.0.1",
		LastHandshake: time.Now().Add(-30 * time.Second),
		Checks:        []domain.HealthCheck{{Name: "warp-egress", OK: true, Detail: "cloudflare"}, {Name: "dns", OK: false}},
	})

	res, body := get(t, h, "/nodes/exit-de-1")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	for _, want := range []string{
		"exit-de-1", "198.51.100.7", // inventory
		"104.16.0.1", "warp-egress", "cloudflare", // status + checks
		"cmark ok", "cmark bad", // check verdict glyphs (shape, not colour-only)
		`aria-label="warp-egress: pass"`, `aria-label="dns: fail"`, // accessible verdict
		"role:    exit", "egress:  warp", "[wg server]", "address pool: 10.81.0.0/24", // rendered spec preview
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail body missing %q", want)
		}
	}
}

func TestMasterDetailShowsWGEasyLink(t *testing.T) {
	h, st := newTestHandler(t, stubRenderer{spec: domain.NodeSpec{Role: domain.RoleMaster}})
	seed(t, st, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, MgmtAddr: "10.20.25.254", State: domain.StateReady})

	_, body := get(t, h, "/nodes/master-xa-1")
	if !strings.Contains(body, "http://10.20.25.254:44423") {
		t.Errorf("master detail missing wg-easy link to its mgmt addr:\n%s", body)
	}

	// An exit node must not show a wg-easy link.
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, MgmtAddr: "10.20.0.5", State: domain.StateReady})
	_, body = get(t, h, "/nodes/exit-de-1")
	if strings.Contains(body, ":44423") {
		t.Error("exit detail should not show a wg-easy link")
	}
}

func TestNodeDetailNotFound(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	res, _ := get(t, h, "/nodes/ghost")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

func TestStaticAssetsServed(t *testing.T) {
	h, _ := newTestHandler(t, nil)
	for _, path := range []string{"/static/app.css", "/static/htmx.min.js"} {
		res, _ := get(t, h, path)
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s status = %d", path, res.StatusCode)
		}
	}
}

func TestFormatSinceBuckets(t *testing.T) {
	cases := map[time.Duration]string{
		5 * time.Second:  "5s ago",
		3 * time.Minute:  "3m ago",
		2 * time.Hour:    "2h ago",
		50 * time.Hour:   "2d ago",
		-1 * time.Second: "just now",
	}
	for d, want := range cases {
		if got := formatSince(d); got != want {
			t.Errorf("formatSince(%v) = %q, want %q", d, got, want)
		}
	}
}

func post(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if hh, ok := h.(*Handler); ok {
		req.Header.Set("X-CSRF-Token", hh.csrf)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestDrainUndrainActions(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	res := post(t, h, "/nodes/exit-de-1/drain")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("drain status = %d, want 303", res.StatusCode)
	}
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); !n.Drain {
		t.Error("drain action did not set the flag")
	}

	res = post(t, h, "/nodes/exit-de-1/undrain")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("undrain status = %d", res.StatusCode)
	}
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); n.Drain {
		t.Error("undrain action did not clear the flag")
	}
}

func TestDeleteAction(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	res := post(t, h, "/nodes/exit-de-1/delete")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete status = %d", res.StatusCode)
	}
	if _, err := st.GetNode(context.Background(), "exit-de-1"); err == nil {
		t.Error("delete action did not remove the node")
	}
}

func TestDeleteGatedOnDecommission(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	// Not decommissioned ⇒ disabled Delete (no form).
	if _, body := get(t, h, "/nodes/exit-de-1"); strings.Contains(body, `action="/nodes/exit-de-1/delete"`) {
		t.Error("delete form should be hidden until the node is decommissioned")
	}

	// Once decommissioned ⇒ the delete form appears.
	_ = st.SetNodeDecommission(context.Background(), "exit-de-1", true)
	if _, body := get(t, h, "/nodes/exit-de-1"); !strings.Contains(body, `action="/nodes/exit-de-1/delete"`) {
		t.Error("decommissioned node should show the delete form")
	}
}

func TestDecommissionGatedOnDrain(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	// Not drained ⇒ decommission is refused (would tear down a live LB target).
	post(t, h, "/nodes/exit-de-1/decommission")
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); n.Decommission {
		t.Fatal("decommission must be refused while the node is still in routing")
	}
	// The disabled button is shown, not the active form.
	if _, body := get(t, h, "/nodes/exit-de-1"); strings.Contains(body, `action="/nodes/exit-de-1/decommission"`) {
		t.Error("decommission form should be hidden (disabled button) until drained")
	}

	// Drain first ⇒ decommission now succeeds.
	_ = st.SetNodeDrain(context.Background(), "exit-de-1", true)
	post(t, h, "/nodes/exit-de-1/decommission")
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); !n.Decommission {
		t.Fatal("decommission should succeed once the node is drained")
	}
}

func TestRecommissionClearsDecommission(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Drain: true, Decommission: true})

	// The cancel-decommission form is offered for a decommissioned node.
	if _, body := get(t, h, "/nodes/exit-de-1"); !strings.Contains(body, `action="/nodes/exit-de-1/recommission"`) {
		t.Error("decommissioned node should offer Cancel decommission")
	}
	post(t, h, "/nodes/exit-de-1/recommission")
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); n.Decommission {
		t.Fatal("recommission must clear the decommission flag")
	}
}

// TestActionErrorRedirectsWithFlash covers the error path: a store mutation that
// fails (here, a drain on a node that does not exist) must redirect back to the
// originating page with a one-shot flash cookie — NOT dump a bare http.Error text
// page. The CSRF guard still gates the request.
func TestActionErrorRedirectsWithFlash(t *testing.T) {
	h, _ := newTestHandler(t, nil) // no node seeded ⇒ the mutation fails

	res := post(t, h, "/nodes/ghost/drain")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("failed action status = %d, want 303 (redirect, not a bare error page)", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/nodes/ghost" {
		t.Errorf("redirect Location = %q, want /nodes/ghost", loc)
	}
	var flashed bool
	for _, c := range res.Cookies() {
		if c.Name == flashCookie && c.Value != "" {
			flashed = true
		}
	}
	if !flashed {
		t.Error("failed action should set a flash cookie carrying the error")
	}

	// The error path is still CSRF-gated: same-origin but no token ⇒ 403, no flash.
	req := httptest.NewRequest(http.MethodPost, "/nodes/ghost/drain", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Errorf("missing-CSRF failed action = %d, want 403", rec.Result().StatusCode)
	}
}

func TestActionsRejectCrossSite(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	req := httptest.NewRequest(http.MethodPost, "/nodes/exit-de-1/drain", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", rec.Result().StatusCode)
	}
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); n.Drain {
		t.Error("cross-site POST must not mutate")
	}
}

func TestActionsRejectMissingCSRF(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	// Same-origin (passes the Sec-Fetch check) but no CSRF token must still 403.
	req := httptest.NewRequest(http.MethodPost, "/nodes/exit-de-1/drain", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Errorf("missing-CSRF POST = %d, want 403", rec.Result().StatusCode)
	}
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); n.Drain {
		t.Error("missing-CSRF POST must not mutate")
	}

	// A wrong token is rejected too.
	req = httptest.NewRequest(http.MethodPost, "/nodes/exit-de-1/drain", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-CSRF-Token", "not-the-real-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Errorf("bad-CSRF POST = %d, want 403", rec.Result().StatusCode)
	}
}

func TestActionFormsCarryCSRFToken(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	res, body := get(t, h, "/nodes/exit-de-1")
	if !strings.Contains(body, `name="csrf_token" value="`+h.csrf+`"`) {
		t.Error("detail page forms missing CSRF token field")
	}
	var found bool
	for _, c := range res.Cookies() {
		if c.Name == csrfCookie && c.Value == h.csrf {
			found = true
		}
	}
	if !found {
		t.Error("detail page did not set the CSRF double-submit cookie")
	}
}

func TestDetailShowsDrainButton(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	_, body := get(t, h, "/nodes/exit-de-1")
	if !strings.Contains(body, `action="/nodes/exit-de-1/drain"`) {
		t.Error("detail page missing drain action")
	}
	// Delete is gated on Decommission: a non-decommissioned node shows a disabled
	// Delete button, not the delete form.
	if strings.Contains(body, `action="/nodes/exit-de-1/delete"`) {
		t.Error("non-decommissioned node should not show an active delete form")
	}
	if !strings.Contains(body, "Decommission and tear down first") {
		t.Error("non-decommissioned node should show the disabled-delete tooltip")
	}
	// Once drained, show undrain + draining badge.
	_ = st.SetNodeDrain(context.Background(), "exit-de-1", true)
	_, body = get(t, h, "/nodes/exit-de-1")
	if !strings.Contains(body, `action="/nodes/exit-de-1/undrain"`) {
		t.Error("drained node should show undrain action")
	}
	if !strings.Contains(body, "badge draining") {
		t.Error("drained node should show draining badge")
	}
}

func TestDetailShowsEgressBlockedBadge(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateDegraded})

	// No status yet ⇒ no badge.
	if _, body := get(t, h, "/nodes/exit-de-1"); strings.Contains(body, "egress blocked") {
		t.Error("node without status should not show the egress-blocked badge")
	}

	// A failing egress-reachability self-check ⇒ blocked badge.
	_ = st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: "exit-de-1",
		State:  domain.StateDegraded,
		Checks: []domain.HealthCheck{
			{Name: domain.CheckEgressReachability, OK: false, Detail: "blocked: WARP path unreachable"},
		},
	})
	if _, body := get(t, h, "/nodes/exit-de-1"); !strings.Contains(body, "egress blocked") {
		t.Error("node with a failing egress-reachability check should show the egress-blocked badge")
	}
}

func TestDetailShowsEgressFailoverBadge(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	// Active egress = direct (failed over) ⇒ failover badge.
	_ = st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: "exit-de-1", State: domain.StateReady,
		Checks: []domain.HealthCheck{{Name: domain.CheckEgressActive, OK: true, Detail: "direct"}},
	})
	if _, body := get(t, h, "/nodes/exit-de-1"); !strings.Contains(body, "egress: direct") {
		t.Error("failed-over node should show the egress failover badge")
	}

	// Active egress = warp (preferred) ⇒ no failover badge.
	_ = st.RecordStatus(context.Background(), domain.NodeStatus{
		NodeID: "exit-de-1", State: domain.StateReady,
		Checks: []domain.HealthCheck{{Name: domain.CheckEgressActive, OK: true, Detail: "warp"}},
	})
	if _, body := get(t, h, "/nodes/exit-de-1"); strings.Contains(body, "egress: warp") {
		t.Error("a node on the preferred egress should not show the failover badge")
	}
}

func TestDecommissionAction(t *testing.T) {
	h, st := newTestHandler(t, nil)
	// Drained first — decommission is gated on Drain (see TestDecommissionGatedOnDrain).
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Drain: true})

	res := post(t, h, "/nodes/exit-de-1/decommission")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("decommission status = %d", res.StatusCode)
	}
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); !n.Decommission {
		t.Error("decommission action did not set the flag")
	}
	_, body := get(t, h, "/nodes/exit-de-1")
	if !strings.Contains(body, "badge decommissioning") {
		t.Error("decommissioning node should show the badge")
	}
}

type stubProv struct {
	provisionable bool
	triggered     string
	upgraded      string
	err           error
	manifest      []domain.Node
}

func (s *stubProv) Provisionable(string) bool { return s.provisionable }
func (s *stubProv) TriggerAsync(id string) error {
	s.triggered = id
	return s.err
}
func (s *stubProv) TriggerUpgrade(id string) error {
	s.upgraded = id
	return s.err
}
func (s *stubProv) ManifestNodes() []domain.Node { return s.manifest }

func newProvHandler(t *testing.T, prov Provisioner) (*Handler, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h, err := New(st, nil, prov, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h, st
}

func TestProvisionAction(t *testing.T) {
	prov := &stubProv{provisionable: true}
	h, st := newProvHandler(t, prov)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StatePending})

	res := post(t, h, "/nodes/exit-de-1/provision")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("provision status = %d", res.StatusCode)
	}
	if prov.triggered != "exit-de-1" {
		t.Errorf("TriggerAsync not called with the node id, got %q", prov.triggered)
	}
}

func TestUpgradeAction(t *testing.T) {
	// A provisioned (Ready) node can have its agent rolled forward. The success
	// path 303-redirects; the failure path flashes-and-redirects (not a bare error).
	prov := &stubProv{provisionable: true}
	h, st := newProvHandler(t, prov)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	res := post(t, h, "/nodes/exit-de-1/upgrade")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("upgrade status = %d, want 303", res.StatusCode)
	}
	if prov.upgraded != "exit-de-1" {
		t.Errorf("TriggerUpgrade not called with the node id, got %q", prov.upgraded)
	}

	// TriggerUpgrade error ⇒ redirect back to the node page with a flash, not 4xx text.
	prov.err = errInjected
	res = post(t, h, "/nodes/exit-de-1/upgrade")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("failed upgrade status = %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/nodes/exit-de-1" {
		t.Errorf("failed upgrade Location = %q, want /nodes/exit-de-1", loc)
	}
	var flashed bool
	for _, c := range res.Cookies() {
		if c.Name == flashCookie && c.Value != "" {
			flashed = true
		}
	}
	if !flashed {
		t.Error("failed upgrade should set a flash cookie")
	}

	// Still CSRF-gated.
	req := httptest.NewRequest(http.MethodPost, "/nodes/exit-de-1/upgrade", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusForbidden {
		t.Errorf("missing-CSRF upgrade = %d, want 403", rec.Result().StatusCode)
	}
}

func TestUpgradeUnavailableWhenNoManager(t *testing.T) {
	h, st := newTestHandler(t, nil) // prov is nil
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})
	res := post(t, h, "/nodes/exit-de-1/upgrade")
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("upgrade without manager = %d, want 503", res.StatusCode)
	}
}

func TestProvisionButtonShownForPending(t *testing.T) {
	prov := &stubProv{provisionable: true}
	h, st := newProvHandler(t, prov)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StatePending})

	_, body := get(t, h, "/nodes/exit-de-1")
	if !strings.Contains(body, `action="/nodes/exit-de-1/provision"`) {
		t.Error("Pending provisionable node should show the Provision button")
	}

	// A Ready node should NOT offer provisioning.
	_ = st.SetNodeState(context.Background(), "exit-de-1", domain.StateReady, "")
	_, body = get(t, h, "/nodes/exit-de-1")
	if strings.Contains(body, `action="/nodes/exit-de-1/provision"`) {
		t.Error("Ready node should not show the Provision button")
	}
}

func TestProvisionUnavailableWhenNoManager(t *testing.T) {
	h, st := newTestHandler(t, nil) // prov is nil
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StatePending})
	res := post(t, h, "/nodes/exit-de-1/provision")
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("provision without manager = %d, want 503", res.StatusCode)
	}
}

func TestManifestNodeShownAsPending(t *testing.T) {
	// A node declared in the manifest but absent from the store must appear
	// (Pending) in the list and be viewable so it can be provisioned.
	prov := &stubProv{
		provisionable: true,
		manifest:      []domain.Node{{ID: "exit-new", Name: "exit-new", Role: domain.RoleExit, State: domain.StatePending}},
	}
	h, _ := newProvHandler(t, prov)

	_, list := get(t, h, "/")
	if !strings.Contains(list, "exit-new") {
		t.Error("manifest-only node should appear in the fleet list")
	}
	res, detail := get(t, h, "/nodes/exit-new")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("manifest node detail = %d, want 200", res.StatusCode)
	}
	if !strings.Contains(detail, `action="/nodes/exit-new/provision"`) {
		t.Error("manifest-only node detail should offer provisioning")
	}
}

func TestTransportSwitchAction(t *testing.T) {
	// A dual-transport exit renders the switch; the POST records the override.
	spec := domain.NodeSpec{
		Role:              domain.RoleExit,
		WGServer:          domain.WGServerSpec{ListenPort: 443, AddressPool: "10.81.0.0/24"},
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		ActiveTransport:   domain.TransportAWG,
		Reality: &domain.RealityServerSpec{
			ListenPort: 8443, ServerName: "www.microsoft.com", Dest: "www.microsoft.com:443",
			UUID: "u", ShortID: "ab",
		},
	}
	h, st := newTestHandler(t, stubRenderer{spec: spec})
	// The handler must durably persist the switch to the manifest before the store.
	var persisted []domain.MasterTransport
	h.persistTransport = func(exitName string, tr domain.MasterTransport) error {
		if exitName != "exit-de-1" {
			t.Errorf("persistTransport exit = %q, want exit-de-1", exitName)
		}
		persisted = append(persisted, tr)
		return nil
	}
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	_, body := get(t, h, "/nodes/exit-de-1")
	for _, want := range []string{
		"Transport", "AmneziaWG", "REALITY", "www.microsoft.com",
		"/nodes/exit-de-1/transport/reality-xhttp",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing transport switch element %q", want)
		}
	}

	res := post(t, h, "/nodes/exit-de-1/transport/reality-xhttp")
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("transport switch status = %d, want 303", res.StatusCode)
	}
	if n, _ := st.GetNode(context.Background(), "exit-de-1"); n.ActiveTransport != domain.TransportRealityXHTTP {
		t.Errorf("override = %q, want reality-xhttp", n.ActiveTransport)
	}
	if len(persisted) != 1 || persisted[0] != domain.TransportRealityXHTTP {
		t.Errorf("manifest persist = %v, want [reality-xhttp]", persisted)
	}

	if res := post(t, h, "/nodes/exit-de-1/transport/carrier-pigeon"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown transport status = %d, want 400", res.StatusCode)
	}
	// An invalid transport must never reach the manifest writer.
	if len(persisted) != 1 {
		t.Errorf("persist called for invalid transport: %v", persisted)
	}
}

func TestListShowsEgressIP(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, PublicIP: "198.51.100.7"})
	_ = st.RecordStatus(context.Background(), domain.NodeStatus{NodeID: "exit-de-1", State: domain.StateReady, EgressIP: "104.16.0.9"})
	_, body := get(t, h, "/")
	if !strings.Contains(body, "104.16.0.9") {
		t.Errorf("fleet list should show the exit's egress IP:\n%s", body)
	}
}

func TestListShowsTransportAndMgmt(t *testing.T) {
	spec := domain.NodeSpec{
		Role:              domain.RoleExit,
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		ActiveTransport:   domain.TransportRealityXHTTP,
	}
	h, st := newTestHandler(t, stubRenderer{spec: spec})
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, MgmtAddr: "10.20.3.22"})
	_, body := get(t, h, "/")
	for _, want := range []string{"10.20.3.22" /* mgmt col back */, "REALITY" /* active transport */, "Mgmt (ZT)"} {
		if !strings.Contains(body, want) {
			t.Errorf("fleet list missing %q:\n%s", want, body)
		}
	}
}
