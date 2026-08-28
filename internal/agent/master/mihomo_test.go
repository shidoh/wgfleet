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
