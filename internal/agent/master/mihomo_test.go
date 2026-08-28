package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The TPROXY listener needs the same self-heal the redirect listener has.
//
// Client UDP is handed to a transparent socket now, and TPROXY to a socket that is
// not there DROPS the datagram. So a lost UDP bind is silent client-side breakage —
// exactly the shape the redirect planner exists to catch on TCP — and nothing was
// watching it: the probe read `ss -ltnH`, which is TCP only.
func TestMihomoRedirPlannerRebindsOnALostTProxyListener(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{BindAddress: "10.80.0.1"}}

	// TCP up, UDP down ⇒ restart.
	p := mihomoRedirPlanner{
		compose:      "/etc/wgfleet/docker-compose.yml",
		listening:    func(string) bool { return true },
		udpListening: func(string) bool { return false },
		localUp:      func(string) bool { return true },
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var restarts bool
	var dump string
	for _, a := range acts {
		dump += a.Summary + " | " + a.Display + "\n"
		if a.Changes() {
			restarts = true
		}
	}
	if !restarts {
		t.Errorf("a lost tproxy listener did not trigger a rebind; client UDP is dropped in silence:\n%s", dump)
	}
	if !strings.Contains(dump, "7896") {
		t.Errorf("the plan does not name the transparent port:\n%s", dump)
	}

	// Both up ⇒ quiet.
	p.udpListening = func(string) bool { return true }
	acts2, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts2 {
		if a.Changes() {
			t.Errorf("both listeners up must be quiet, got %q", a.Summary)
		}
	}
}

// A spec mihomo cannot render must defer THIS component, not abort the pass.
//
// The engine stops at the first planner error and this planner runs ahead of the
// master NAT, DOCKER-USER, blocky and the VLESS inbound. So "every exit is drained"
// — a condition the controller can produce and the node cannot fix — used to stop
// the master converging its own firewall. A master that rebooted in that state came
// back with no client DNAT, no TPROXY and no masquerade, and the self-heal branches
// written for exactly that never got to run.
func TestMihomoPlannerDefersInsteadOfAbortingThePass(t *testing.T) {
	p := mihomoPlanner{paths: PathsUnder(t.TempDir()), privateKey: "k"}
	// No exit tunnels at all: RenderConfig refuses this, by design.
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{BindAddress: "10.80.0.1"}}

	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v; an unrenderable spec must not fail the pass", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Summary + "\n"
		if a.Changes() {
			t.Errorf("a deferred pass must change nothing, got %q", a.Summary)
		}
	}
	if !strings.Contains(dump, "keeping the last-good config") {
		t.Errorf("the deferral does not say why:\n%s", dump)
	}
}
