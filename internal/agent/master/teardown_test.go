package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Decommission means the node's identity is destroyed with it. The client leg is
// the one that carries end users, so leaving it up on a retired master keeps
// serving them, and leaving its files behind leaves the interface private key
// AND every client's preshared key on a VPS that goes back to the provider.
//
// Before the agent owned this interface, `docker compose down` took it with the
// container; owning it means owning its teardown too.
func TestMasterTeardownRetiresTheClientInterface(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	planners := TeardownPlanners(paths)

	var summaries, targets []string
	for _, p := range planners {
		actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		for _, a := range actions {
			summaries = append(summaries, a.Summary)
			targets = append(targets, a.Target)
		}
	}
	all := strings.Join(summaries, "\n")
	if !strings.Contains(all, "client interface down") {
		t.Errorf("teardown leaves the client interface up:\n%s", all)
	}

	joined := strings.Join(targets, "\n")
	for _, secret := range []string{paths.ClientWGConf, paths.ClientWGKey} {
		if !strings.Contains(joined, secret) {
			t.Errorf("teardown leaves %s on disk — it holds the interface key and every client's preshared key", secret)
		}
	}
}

// The client-VLESS secrets (ADR-0031) must still be wiped: these assertions were
// guarding that before this branch and were lost when the file was rewritten.
func TestMasterTeardownWipesEveryNodeSecret(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	var targets, summaries []string
	for _, p := range TeardownPlanners(paths) {
		actions, err := p.Plan(context.Background(), domain.NodeSpec{Role: domain.RoleMaster})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		for _, a := range actions {
			targets = append(targets, a.Target)
			summaries = append(summaries, a.Summary)
		}
	}
	joined := strings.Join(targets, "\n")
	for _, secret := range []string{
		paths.ClientVLESS,    // REALITY private key + every issued client UUID
		paths.ClientVLESSKey, // the master's client-facing REALITY key
		paths.WGEasyDB,       // wg-easy's client database, keys included
		paths.ClientWGConf,   // interface key + every client preshared key
		paths.ClientWGKey,
		ClaimPathFor(paths.ClientWGConf),
	} {
		if !strings.Contains(joined, secret) {
			t.Errorf("teardown leaves %s on a decommissioned host", secret)
		}
	}
	// And the node's tables go with it.
	all := strings.Join(summaries, "\n")
	for _, want := range []string{"master NAT table", "input-firewall table", "container stack down"} {
		if !strings.Contains(all, want) {
			t.Errorf("teardown no longer removes %q", want)
		}
	}
}
