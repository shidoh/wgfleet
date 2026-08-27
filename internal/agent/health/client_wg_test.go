package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The check exists because "an interface named wg0 is up" is also true while
// wg-easy holds it, and stays true through every deferral the interface planner
// can report. Without the claim, those states would leave the node green.
func TestClientWGOwnedProbeRequiresTheClaim(t *testing.T) {
	claim := filepath.Join(t.TempDir(), "wg0.conf.claim")
	res := ClientWGOwnedProbe(claim, "wg0")(context.Background())
	if res.OK {
		t.Fatal("probe passed with no claim recorded")
	}
	if !strings.Contains(res.Detail, "has not raised") {
		t.Fatalf("detail = %q, want it to name the missing claim", res.Detail)
	}

	// With a claim but no such interface it must still fail — a claim alone is a
	// record of intent, not of a working data plane.
	if err := os.WriteFile(claim, []byte("claimed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = ClientWGOwnedProbe(claim, "wgfleet-no-such-iface")(context.Background())
	if res.OK {
		t.Fatal("probe passed for an interface that does not exist")
	}
	if !strings.Contains(res.Detail, "not up") {
		t.Fatalf("detail = %q, want it to say the interface is down", res.Detail)
	}
}

// The check is wired only when the agent owns the leg: on a master still running
// wg-easy it must not appear at all, or every un-migrated node would report a
// failure for a component it does not have.
func TestMasterChecksWiresClientWGOnlyWhenManaged(t *testing.T) {
	probes := MasterProbes{
		WGServerUp:    func(context.Context) Result { return Result{OK: true} },
		ClientWGOwned: func(context.Context) Result { return Result{OK: true} },
	}
	unmanaged := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	for _, c := range MasterChecks(unmanaged, probes) {
		if c.Name == "client-wg-owned" {
			t.Fatal("an unmanaged master reports a client-wg-owned check")
		}
	}

	managed := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		ClientWG: &domain.ClientWGSpec{ListenPort: 443, AddressPool: "10.80.0.0/24"},
	}}
	var found bool
	for _, c := range MasterChecks(managed, probes) {
		if c.Name == "client-wg-owned" {
			found = true
		}
	}
	if !found {
		t.Fatal("a managed master does not report whether it owns the client interface")
	}
}
