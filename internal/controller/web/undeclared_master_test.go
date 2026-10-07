package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

const notInManifest = `>NOT IN MANIFEST<`

// A master taken out of the manifest keeps its store row: it stops being a trunk,
// and without a place on the page it would be a node the console cannot show,
// whose staleness alerts nobody can clear. It gets its own labelled group.
func TestFleetListsAMasterTheManifestDroppedInItsOwnGroup(t *testing.T) {
	h, st := newTestHandler(t, nil)
	h.SetDevices(&fakeDevices{masters: []string{"master-xa-1"}})
	seed(t, st, masterNode("master-xa-1"))
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	// A one-master fleet with nothing left over: the group is not there at all.
	if body := fleetBody(t, h); strings.Contains(body, notInManifest) {
		t.Fatal("the group is rendered with no undeclared master in it")
	}

	seed(t, st, masterNode("master-xa-old"))
	body := fleetBody(t, h)
	if n := strings.Count(body, `class="topo-trunk"`); n != 1 {
		t.Errorf("want exactly one trunk, got %d: an undeclared master is not a master of this fleet", n)
	}
	i := strings.Index(body, notInManifest)
	if i < 0 {
		t.Fatalf("no NOT IN MANIFEST group on the page:\n%s", body)
	}
	if !strings.Contains(body, `title="Registered as a master but not declared in the manifest. Delete it from its page once it is gone for good."`) {
		t.Error("the group's label does not say what it is and what to do about it")
	}
	group := body[i:]
	if !strings.Contains(group, `href="/nodes/master-xa-old"`) {
		t.Errorf("the undeclared master's row does not link to its page:\n%s", group)
	}
	if strings.Contains(group, "exit-de-1") {
		t.Error("an exit is listed under the undeclared master")
	}
	// The declared master and the exit are where they were, above the group.
	if j := strings.Index(body, `class="topo-trunk"`); j < 0 || j > i {
		t.Error("the group is not below the manifest masters")
	}
	if strings.Contains(body[:i], "master-xa-old") {
		t.Error("the undeclared master also appears outside its group")
	}

	// The polled fragment renders the same.
	if _, partial := get(t, h, "/partials/nodes"); !strings.Contains(partial, notInManifest) {
		t.Error("the polled fleet fragment drops the group")
	}
}

// Without a manifest source the store's master rows stand in for the manifest,
// so there is no telling a dropped master from a declared one: none is "not in
// the manifest".
func TestFleetWithoutAManifestSourceHasNoUndeclaredMasters(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, masterNode("master-xa-1"))
	seed(t, st, masterNode("master-xa-2"))
	if body := fleetBody(t, h); strings.Contains(body, notInManifest) {
		t.Error("a handler with no manifest source called a master undeclared")
	}
}

// Deleting THE master used to be fatal, so the console refused it for every
// master. One the manifest no longer declares is not the master of anything: it
// can go, and the confirmation says what goes with it.
func TestAnUndeclaredMasterIsDeletable(t *testing.T) {
	h, st := newTestHandler(t, nil)
	h.SetDevices(&fakeDevices{masters: []string{"master-xa-1"}})
	ctx := context.Background()
	seed(t, st, masterNode("master-xa-1"))
	seed(t, st, masterNode("master-xa-old"))
	for _, m := range []string{"master-xa-1", "master-xa-old"} {
		if err := st.AddWGClient(ctx, m, domain.WGClient{ID: "c-" + m, Name: "laptop", Address: "10.80.0.2/32",
			PublicKey: "pub-" + m, PrivateKey: "priv-" + m, Enabled: true, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := st.AddVLESSClient(ctx, m, domain.VLESSClient{Name: "phone", UUID: "11111111-1111-4111-8111-111111111111", ShortID: "ab"}); err != nil {
			t.Fatal(err)
		}
	}

	_, page := get(t, h, "/nodes/master-xa-old")
	if !strings.Contains(page, `action="/nodes/master-xa-old/delete"`) {
		t.Fatal("the undeclared master's page offers no Delete")
	}
	if !strings.Contains(page, "not declared in the manifest") {
		t.Error("the page does not say why this master can be deleted")
	}
	for _, s := range []string{"/drain", "/decommission"} {
		if strings.Contains(page, `action="/nodes/master-xa-old`+s+`"`) {
			t.Errorf("the undeclared master's page offers %s: the routing lifecycle is the exits'", s)
		}
	}

	res := post(t, h, "/nodes/master-xa-old/delete")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("unconfirmed delete status = %d, want the confirmation page", res.StatusCode)
	}
	raw, _ := io.ReadAll(res.Body)
	confirm := string(raw)
	for _, want := range []string{"Delete master-xa-old?", "client credentials", "WireGuard", "VLESS", "device"} {
		if !strings.Contains(confirm, want) {
			t.Errorf("the confirmation does not mention %q:\n%s", want, confirm)
		}
	}
	if _, err := st.GetNode(ctx, "master-xa-old"); err != nil {
		t.Fatal("an unconfirmed delete removed the master anyway")
	}

	res = postWith(t, h, "/nodes/master-xa-old/delete", url.Values{"confirm": {"1"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("confirmed delete: status %d to %q, want 303 to the fleet page", res.StatusCode, res.Header.Get("Location"))
	}
	if _, err := st.GetNode(ctx, "master-xa-old"); err == nil {
		t.Error("the undeclared master is still in the store")
	}
	// What the confirmation promised is what happened — and only to that master.
	if wgc, _ := st.ListWGClients(ctx, "master-xa-old"); len(wgc) != 0 {
		t.Errorf("%d WireGuard credential(s) of the deleted master survived", len(wgc))
	}
	if vc, _ := st.ListVLESSClients(ctx, "master-xa-old"); len(vc) != 0 {
		t.Errorf("%d VLESS credential(s) of the deleted master survived", len(vc))
	}
	if wgc, _ := st.ListWGClients(ctx, "master-xa-1"); len(wgc) != 1 {
		t.Errorf("the declared master has %d WireGuard credential(s) left, want its 1", len(wgc))
	}
	if strings.Contains(fleetBody(t, h), notInManifest) {
		t.Error("the group is still on the fleet page after its only master was deleted")
	}
}

// The other half: a master the manifest declares is still refused, on the page
// and as a plain POST, confirmed or not.
func TestADeclaredMasterIsStillNotDeletable(t *testing.T) {
	cases := map[string]func(h *Handler){
		"declared in the manifest": func(h *Handler) { h.SetDevices(&fakeDevices{masters: []string{"master-xa-1", "master-xa-2"}}) },
		// No manifest to check against: refusing is the safe side.
		"no manifest source": func(*Handler) {},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			h, st := newTestHandler(t, nil)
			wire(h)
			seed(t, st, masterNode("master-xa-1"))
			seed(t, st, masterNode("master-xa-2"))

			if _, page := get(t, h, "/nodes/master-xa-2"); strings.Contains(page, "/delete") {
				t.Error("a declared master's page offers Delete")
			}
			res := postWith(t, h, "/nodes/master-xa-2/delete", url.Values{"confirm": {"1"}})
			if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/nodes/master-xa-2" {
				t.Fatalf("delete of a declared master: status %d to %q, want a refusal back to its page",
					res.StatusCode, res.Header.Get("Location"))
			}
			if _, err := st.GetNode(context.Background(), "master-xa-2"); err != nil {
				t.Fatal("a declared master was deleted")
			}
		})
	}
}

// The store row's role is what the node said about itself. A node the manifest
// declares — as an exit here — is a node of this fleet whatever its row says: it
// is not a leftover master, is not listed as one, and is not deletable as one
// (that path skips the drain→decommission order an exit is owed).
func TestADeclaredNodeWithAMasterRowIsNotAnUndeclaredMaster(t *testing.T) {
	prov := &stubProv{manifest: []domain.Node{
		{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StatePending},
		{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StatePending},
	}}
	h, st := newProvHandler(t, prov)
	h.SetDevices(&fakeDevices{masters: []string{"master-xa-1"}})
	seed(t, st, masterNode("master-xa-1"))
	seed(t, st, masterNode("exit-de-1")) // declared an exit; its row says master

	if body := fleetBody(t, h); strings.Contains(body, notInManifest) {
		t.Error("a node the manifest declares is listed under NOT IN MANIFEST")
	}
	if _, page := get(t, h, "/nodes/exit-de-1"); strings.Contains(page, `action="/nodes/exit-de-1/delete"`) {
		t.Error("its page offers the undeclared-master Delete")
	}
	res := postWith(t, h, "/nodes/exit-de-1/delete", url.Values{"confirm": {"1"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/nodes/exit-de-1" {
		t.Fatalf("delete: status %d to %q, want a refusal back to its page", res.StatusCode, res.Header.Get("Location"))
	}
	if _, err := st.GetNode(context.Background(), "exit-de-1"); err != nil {
		t.Fatal("a node the manifest declares was deleted as an undeclared master")
	}
}
