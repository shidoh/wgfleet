package keybroker

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
)

func boolp(b bool) *bool { return &b }

// The rendered spec must always state the policy, even when the manifest says
// nothing: an unset field on the wire means "controller predates the knob", and a
// current controller must never send that.
func TestRenderNodeSpecAlwaysStatesHardening(t *testing.T) {
	b, _ := newBroker(t)
	for _, id := range []string{"exit-de-1", "master-xa-1"} {
		spec, err := b.RenderNodeSpec(context.Background(), id)
		if err != nil {
			t.Fatalf("RenderNodeSpec(%s): %v", id, err)
		}
		if spec.Hardening == nil {
			t.Fatalf("%s: Hardening = nil; the controller must state its intent explicitly", id)
		}
		if !spec.SSHDHardeningEnabled() || !spec.Fail2banEnabled() {
			t.Errorf("%s: default manifest must render both subsystems enabled, got %+v", id, spec.Hardening)
		}
	}
}

// The case the per-node override exists for: keep a hand-tuned sshd_config on the
// master — the box the operator actually logs into — WITHOUT un-hardening the
// public-facing exits. A fleet-only knob could not express this.
func TestRenderNodeSpecMasterOptsOutAlone(t *testing.T) {
	fleet := testFleet()
	fleet.Masters[0].Hardening = config.HardeningSection{SSHD: boolp(false)}
	b, _ := newBrokerWithFleet(t, fleet)

	master, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("RenderNodeSpec(master): %v", err)
	}
	if master.SSHDHardeningEnabled() {
		t.Error("master must honour its own sshd opt-out")
	}
	if !master.Fail2banEnabled() {
		t.Error("opting out of sshd must not also drop the fail2ban jail")
	}

	exit, err := b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatalf("RenderNodeSpec(exit): %v", err)
	}
	if !exit.SSHDHardeningEnabled() {
		t.Error("a master-scoped opt-out must not reach the exits — that inverts the intent")
	}
}

// The inverse direction: a fleet-wide opt-out with one node re-hardening itself.
// Without this the override could only ever weaken a node, never protect one.
func TestRenderNodeSpecNodeReEnablesAgainstFleetOff(t *testing.T) {
	fleet := testFleet()
	fleet.Hardening = config.HardeningSection{SSHD: boolp(false), Fail2ban: boolp(false)}
	fleet.Exits[0].Hardening = config.HardeningSection{SSHD: boolp(true), Fail2ban: boolp(true)}
	b, _ := newBrokerWithFleet(t, fleet)

	exit, err := b.RenderNodeSpec(context.Background(), "exit-de-1")
	if err != nil {
		t.Fatalf("RenderNodeSpec(exit): %v", err)
	}
	if !exit.SSHDHardeningEnabled() || !exit.Fail2banEnabled() {
		t.Errorf("exit re-enabling must beat the fleet default, got %+v", exit.Hardening)
	}

	master, err := b.RenderNodeSpec(context.Background(), "master-xa-1")
	if err != nil {
		t.Fatalf("RenderNodeSpec(master): %v", err)
	}
	if master.SSHDHardeningEnabled() || master.Fail2banEnabled() {
		t.Errorf("master without an override must inherit the fleet opt-out, got %+v", master.Hardening)
	}
}
