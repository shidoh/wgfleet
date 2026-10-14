package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

func sdServer(t *testing.T, blockyPort func(string) int) (store.Store, http.Handler) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	for _, n := range []domain.Node{
		{ID: "master-1", Name: "master-1", Role: domain.RoleMaster, MgmtAddr: "10.20.0.1", State: domain.StateReady},
		{ID: "exit-b", Name: "exit-b", Role: domain.RoleExit, MgmtAddr: "10.20.0.3", State: domain.StateReady},
		{ID: "exit-a", Name: "exit-a", Role: domain.RoleExit, MgmtAddr: "10.20.0.2", State: domain.StateDegraded},
		// Declared but never provisioned: nothing to dial yet.
		{ID: "exit-new", Name: "exit-new", Role: domain.RoleExit, State: domain.StatePending},
	} {
		if err := st.UpsertNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	return st, SDHandler(st, SDConfig{ControllerAddr: "10.20.0.1:9300", BlockyPort: blockyPort})
}

func getSD(t *testing.T, h http.Handler, path string) []SDGroup {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, body %q", path, rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("GET %s: Content-Type %q, Prometheus HTTP SD requires application/json", path, ct)
	}
	var out []SDGroup
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: not SD JSON: %v", path, err)
	}
	return out
}

func TestSDWgfleetJobListsControllerAndEveryAgent(t *testing.T) {
	_, h := sdServer(t, func(string) int { return 4000 })
	got := getSD(t, h, "/sd/wgfleet")
	want := []SDGroup{
		{Targets: []string{"10.20.0.1:9300"}, Labels: map[string]string{"component": "controller"}},
		// No node/role target labels: the agent stamps both on its own series, and a
		// target label of the same name would push them to exported_node.
		{Targets: []string{"10.20.0.2:9301"}, Labels: map[string]string{"component": "agent", "__meta_wgfleet_node": "exit-a", "__meta_wgfleet_role": "exit"}},
		{Targets: []string{"10.20.0.3:9301"}, Labels: map[string]string{"component": "agent", "__meta_wgfleet_node": "exit-b", "__meta_wgfleet_role": "exit"}},
		{Targets: []string{"10.20.0.1:9301"}, Labels: map[string]string{"component": "agent", "__meta_wgfleet_node": "master-1", "__meta_wgfleet_role": "master"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("/sd/wgfleet\n got: %+v\nwant: %+v", got, want)
	}
}

func TestSDNodeExporterAndBlockyCarryNodeLabels(t *testing.T) {
	ports := map[string]int{"master-1": 4000, "exit-a": 4100, "exit-b": 0} // exit-b runs no blocky
	_, h := sdServer(t, func(n string) int { return ports[n] })

	ne := getSD(t, h, "/sd/node-exporter")
	wantNE := []SDGroup{
		{Targets: []string{"10.20.0.2:9100"}, Labels: map[string]string{"node": "exit-a", "role": "exit"}},
		{Targets: []string{"10.20.0.3:9100"}, Labels: map[string]string{"node": "exit-b", "role": "exit"}},
		{Targets: []string{"10.20.0.1:9100"}, Labels: map[string]string{"node": "master-1", "role": "master"}},
	}
	if !reflect.DeepEqual(ne, wantNE) {
		t.Errorf("/sd/node-exporter\n got: %+v\nwant: %+v", ne, wantNE)
	}

	bl := getSD(t, h, "/sd/blocky")
	wantBL := []SDGroup{
		{Targets: []string{"10.20.0.2:4100"}, Labels: map[string]string{"node": "exit-a", "role": "exit"}},
		{Targets: []string{"10.20.0.1:4000"}, Labels: map[string]string{"node": "master-1", "role": "master"}},
	}
	if !reflect.DeepEqual(bl, wantBL) {
		t.Errorf("/sd/blocky\n got: %+v\nwant: %+v", bl, wantBL)
	}
}

func TestSDUnknownJobIs404(t *testing.T) {
	_, h := sdServer(t, func(string) int { return 4000 })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sd/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown job: status %d, want 404", rec.Code)
	}
}

// A store read error must fail the request, not answer an empty list: Prometheus
// treats an empty target list as "there are no targets" and drops every one it
// had, which turns a locked database into a fleet-wide scrape outage.
func TestSDStoreErrorIsAnErrorNotAnEmptyFleet(t *testing.T) {
	st, h := sdServer(t, func(string) int { return 4000 })
	_ = st.Close()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sd/node-exporter", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("store error: status %d, want 503 so the scraper keeps its last good list", rec.Code)
	}
}
