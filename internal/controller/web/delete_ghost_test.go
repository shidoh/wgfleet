package web

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// ghostHandler builds a handler whose provisioner declares `declared` in the
// manifest, recording every manifest removal the delete performs.
func ghostHandler(t *testing.T, declared ...domain.Node) (*Handler, store.Store, *[]string) {
	t.Helper()
	removed := &[]string{}
	prov := &stubProv{manifest: declared}
	h, st := newProvHandler(t, prov)
	h.removeFromManifest = func(name string) error {
		*removed = append(*removed, name)
		return nil
	}
	return h, st, removed
}

// The fn7 case: a node declared in the manifest whose server is gone and whose
// store row is already gone. It renders as a Pending card, and before this fix
// every lifecycle action was unreachable — Drain failed with "store: not found",
// which permanently gated Decommission, which permanently gated Delete. The node
// could not be removed from the console at all.
func TestDeleteIsOfferedForAManifestOnlyNode(t *testing.T) {
	h, _, _ := ghostHandler(t, domain.Node{ID: "fn7", Name: "fn7", Role: domain.RoleExit, State: domain.StatePending})

	_, body := get(t, h, "/nodes/fn7")

	if !strings.Contains(body, `action="/nodes/fn7/delete"`) {
		t.Errorf("a node with no store row must offer Delete — there is nothing live to drain first:\n%s", body)
	}
}

func TestDeleteRemovesAManifestOnlyNodeFromTheManifest(t *testing.T) {
	h, _, removed := ghostHandler(t, domain.Node{ID: "fn7", Name: "fn7", Role: domain.RoleExit, State: domain.StatePending})

	res := postWith(t, h, "/nodes/fn7/delete", url.Values{"confirm": {"1"}})

	if res.StatusCode != 303 {
		t.Fatalf("delete status = %d, want 303", res.StatusCode)
	}
	if len(*removed) != 1 || (*removed)[0] != "fn7" {
		t.Fatalf("manifest removals = %v, want [fn7] — without this the node returns as a Pending card on the next page load", *removed)
	}
}

// A registered node's delete must take the declaration with it too, or the node
// comes straight back as a Pending stub and the button's "removes the node
// permanently" copy is a lie.
func TestDeleteRemovesTheDeclarationOfARegisteredNode(t *testing.T) {
	h, st, removed := ghostHandler(t, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit})
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})

	res := postWith(t, h, "/nodes/exit-de-1/delete", url.Values{"confirm": {"1"}})

	if res.StatusCode != 303 {
		t.Fatalf("delete status = %d, want 303", res.StatusCode)
	}
	if _, err := st.GetNode(context.Background(), "exit-de-1"); err == nil {
		t.Error("store row survived the delete")
	}
	if len(*removed) != 1 || (*removed)[0] != "exit-de-1" {
		t.Errorf("manifest removals = %v, want [exit-de-1]", *removed)
	}
}

// A node that registered on its own but was never declared in the manifest has no
// block to remove. That is a normal shape, not an error: the delete must not try
// to remove a declaration that was never there and report a failure for it.
func TestDeleteOfAnUndeclaredNodeSkipsTheManifest(t *testing.T) {
	h, st, removed := ghostHandler(t) // manifest declares nothing
	seed(t, st, domain.Node{ID: "rogue", Name: "rogue", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})

	res := postWith(t, h, "/nodes/rogue/delete", url.Values{"confirm": {"1"}})

	if res.StatusCode != 303 {
		t.Fatalf("delete status = %d, want 303", res.StatusCode)
	}
	if _, err := st.GetNode(context.Background(), "rogue"); err == nil {
		t.Error("store row survived the delete")
	}
	if len(*removed) != 0 {
		t.Errorf("manifest removals = %v, want none for an undeclared node", *removed)
	}
}

// Retry must converge. If the manifest write failed the first time, the store row
// is already gone; a second attempt has to finish the job rather than fail on the
// missing row and strand the ghost forever.
func TestDeleteRetryConvergesAfterAPartialFailure(t *testing.T) {
	h, st, removed := ghostHandler(t, domain.Node{ID: "fn7", Name: "fn7", Role: domain.RoleExit})
	seed(t, st, domain.Node{ID: "fn7", Name: "fn7", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})

	// First attempt: the store row goes, the manifest write fails.
	// A failed manifest write redirects back to the node page with the reason in a
	// flash, not to the fleet list — the delete did not complete.
	h.removeFromManifest = func(string) error { return context.DeadlineExceeded }
	res := postWith(t, h, "/nodes/fn7/delete", url.Values{"confirm": {"1"}})
	if loc := res.Header.Get("Location"); loc != "/nodes/fn7" {
		t.Fatalf("failed manifest write redirected to %q, want back to the node page with the error", loc)
	}
	if _, err := st.GetNode(context.Background(), "fn7"); err == nil {
		t.Fatal("precondition: the store row should already be gone")
	}

	// Second attempt: no store row left, and it must still remove the declaration.
	h.removeFromManifest = func(name string) error {
		*removed = append(*removed, name)
		return nil
	}
	res = postWith(t, h, "/nodes/fn7/delete", url.Values{"confirm": {"1"}})
	if res.StatusCode != 303 {
		t.Fatalf("retry status = %d, want 303 — a missing store row must not block the retry", res.StatusCode)
	}
	if len(*removed) != 1 || (*removed)[0] != "fn7" {
		t.Errorf("manifest removals on retry = %v, want [fn7]", *removed)
	}
}

// The other half of the trap: the ghost used to render an enabled "Take out of
// routing" whose only possible outcome was store: not found — and Drain gates
// Decommission, which gates Delete. Offering an action that cannot succeed is what
// made the node look removable while being permanently stuck at step one.
func TestManifestOnlyNodeDoesNotOfferActionsThatCanOnlyFail(t *testing.T) {
	h, _, _ := ghostHandler(t, domain.Node{ID: "fn7", Name: "fn7", Role: domain.RoleExit, State: domain.StatePending})

	_, body := get(t, h, "/nodes/fn7")

	for _, action := range []string{`action="/nodes/fn7/drain"`, `action="/nodes/fn7/decommission"`} {
		if strings.Contains(body, action) {
			t.Errorf("page still posts %s, which can only return store: not found", action)
		}
	}
}

// ManifestNodes() returns masters too, and this handler is reachable as a plain
// POST even though the template hides the buttons for a master. Undeclaring the
// master is silent damage: a master-less manifest still loads, so the controller
// restarts clean and brokers a fleet with no hub.
func TestDeleteNeverUndeclaresAMaster(t *testing.T) {
	h, st, removed := ghostHandler(t, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster})
	seed(t, st, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster, State: domain.StateReady})

	postWith(t, h, "/nodes/master-xa-1/delete", url.Values{"confirm": {"1"}})

	if len(*removed) != 0 {
		t.Errorf("delete tried to remove a MASTER from the manifest: %v", *removed)
	}
}

// The SECOND lock, which the test above never reaches: the first gate reads the
// role off the store row, so a store row saying "exit" walks straight past it. If
// the manifest declares that same name as a MASTER — a rename across the two
// sections, or a store row left over from before one — the manifest removal is the
// only thing standing between a stale row and a fleet that loses its hub.
func TestDeleteWontUndeclareAMasterThatTheStoreCallsAnExit(t *testing.T) {
	h, st, removed := ghostHandler(t, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster})
	// The store disagrees with the manifest about what this node is.
	seed(t, st, domain.Node{ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleExit, State: domain.StateReady, Decommission: true})

	postWith(t, h, "/nodes/master-xa-1/delete", url.Values{"confirm": {"1"}})

	if len(*removed) != 0 {
		t.Errorf("a stale store row got a MASTER undeclared from the manifest: %v", *removed)
	}
}

// The page hides Delete behind role==exit and CanDelete, but hiding a control is a
// UI decision, not an access rule — this handler is reachable as a plain POST. The
// store cascades every client credential on the node and the delete now drops its
// manifest block, so an unchecked POST is no longer a recoverable mistake.
func TestDeleteRefusesALiveExitThatWasNotDecommissioned(t *testing.T) {
	h, st, removed := ghostHandler(t, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit})
	seed(t, st, domain.Node{ID: "exit-de-1", Name: "exit-de-1", Role: domain.RoleExit, State: domain.StateReady})

	postWith(t, h, "/nodes/exit-de-1/delete", url.Values{"confirm": {"1"}})

	if _, err := st.GetNode(context.Background(), "exit-de-1"); err != nil {
		t.Error("a live, non-decommissioned exit was deleted by a direct POST")
	}
	if len(*removed) != 0 {
		t.Errorf("its manifest declaration was removed too: %v", *removed)
	}
}

// The controller reads the manifest once at startup and never reloads it, so after
// a successful delete ManifestNodes() keeps offering the node from its startup
// snapshot: the card comes back and the operator presses Delete again. The second
// press must not report a failure — the file already says what they asked for.
func TestSecondDeleteOnAStaleCardIsNotAnError(t *testing.T) {
	h, _, _ := ghostHandler(t, domain.Node{ID: "fn7", Name: "fn7", Role: domain.RoleExit, State: domain.StatePending})
	h.removeFromManifest = func(string) error {
		return fmt.Errorf("exit %q in manifest %q: %w", "fn7", "/etc/wgfleet/controller.yaml", config.ErrExitNotDeclared)
	}

	res := postWith(t, h, "/nodes/fn7/delete", url.Values{"confirm": {"1"}})

	if loc := res.Header.Get("Location"); loc != "/" {
		t.Errorf("second delete redirected to %q, want the fleet list — an already-absent declaration is the end state, not a failure", loc)
	}
}

// The routing lifecycle is exit-only — the node template says so and hides the
// buttons for a master — but only Delete enforced it. Drain and Decommission are
// reachable as plain POSTs, and a decommissioned MASTER is not a small mistake:
// agent/master/teardown.go wipes ClientWGConf, ClientWGKey, ClientVLESS and
// ClientVLESSKey, i.e. the master's client-facing identity. Every config in the
// field pins the old public key, and a re-provision mints a new one — so it is the
// awg3 `full` flag day, with no warning and no key handed out in advance.
func TestMasterLifecycleActionsAreRefusedServerSide(t *testing.T) {
	for _, action := range []string{"drain", "decommission"} {
		t.Run(action, func(t *testing.T) {
			h, st := newTestHandler(t, nil)
			seed(t, st, domain.Node{
				ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
				State: domain.StateReady, Drain: true, // drained, so only the role can refuse
			})

			postWith(t, h, "/nodes/master-xa-1/"+action, url.Values{"confirm": {"1"}})

			n, err := st.GetNode(context.Background(), "master-xa-1")
			if err != nil {
				t.Fatal(err)
			}
			if n.Decommission {
				t.Error("a plain POST decommissioned the MASTER — its teardown wipes the client-facing keys")
			}
			if action == "drain" && !n.Drain {
				t.Error("the pre-set drain flag was cleared by a refused action")
			}
		})
	}
}

// The UNDO directions must never be role-gated. A master that somehow carries
// Decommission=true — a build before the gate existed could set one with a plain
// POST — has no other way back: there is no CLI equivalent, so a gate here would
// leave raw SQL against the store as the only recovery.
func TestUndoActionsStayAvailableForAMaster(t *testing.T) {
	h, st := newTestHandler(t, nil)
	seed(t, st, domain.Node{
		ID: "master-xa-1", Name: "master-xa-1", Role: domain.RoleMaster,
		State: domain.StateReady, Drain: true, Decommission: true,
	})

	postWith(t, h, "/nodes/master-xa-1/recommission", url.Values{"confirm": {"1"}})
	postWith(t, h, "/nodes/master-xa-1/undrain", url.Values{"confirm": {"1"}})

	n, err := st.GetNode(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatal(err)
	}
	if n.Decommission {
		t.Error("recommission was refused for a master — the console cannot undo a decommission it did not prevent")
	}
	if n.Drain {
		t.Error("undrain was refused for a master — a node cannot be returned to routing")
	}
}
