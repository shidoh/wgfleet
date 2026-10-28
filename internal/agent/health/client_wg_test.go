package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The check exists because "an interface named wg0 is up" is also true when
// something else raised it, and stays true through every deferral the interface
// planner can report. Without the claim, those states would leave the node green.
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

// The check is wired only when the master has a client interface: without one it
// must not appear at all, or the node would report a failure for a component it
// does not have.
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

// A bare `ip link show` cannot see a DECISION. awgl0 stays up from the last good
// config through every deferral the lifeline planner can report — no key yet, a
// rejected spec, AmneziaWG 3.x refused — so without reading the planner's own
// verdict the check reports green on an exit whose reserve peers stopped being
// updated days ago. That includes a revoked credential still being served.
func TestLifelineUpProbeReadsTheDeferral(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "awgl0.conf")

	// No marker: the probe falls through to the link check, which fails for an
	// interface that does not exist — and says so in the interface's own words.
	res := LifelineUpProbe(conf, "wgfleet-no-such-iface")(context.Background())
	if res.OK {
		t.Fatal("probe passed for an interface that does not exist")
	}
	if strings.Contains(res.Detail, "not applying") {
		t.Fatalf("detail = %q, want the link-probe failure, not a deferral", res.Detail)
	}

	// A marker outranks the link probe: even the interface the probe can actually
	// find (loopback here — always up, so the link check would pass) must report
	// the reason the planner is standing still.
	const reason = "spec rejected, keeping the last-good config: listen port 0 out of range"
	if err := os.WriteFile(conf+".deferred", []byte(reason+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = LifelineUpProbe(conf, "lo")(context.Background())
	if res.OK {
		t.Fatal("probe passed while the planner is refusing to apply the lifeline spec")
	}
	if !strings.Contains(res.Detail, "not applying the lifeline spec") || !strings.Contains(res.Detail, reason) {
		t.Fatalf("detail = %q, want it to carry the planner's reason", res.Detail)
	}
}
