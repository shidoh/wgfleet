package config

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestPerTunnelKeyPhaseValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		// Unset is the pre-ADR-0030 default; every existing manifest must stay valid.
		{"unset defaults to off", "", false},
		{"off", "off", false},
		{"dual", "dual", false},
		{"switch", "switch", false},
		{"on", "on", false},
		// A typo must fail the manifest rather than silently reading as "off" — the
		// operator would think a migration step had been applied when it had not.
		{"typo", "duel", true},
		{"boolean-ish", "true", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := validExit()
			e.PerTunnelKey = tc.value
			err := controllerWithExit(e).Validate()
			gotErr := err != nil && strings.Contains(err.Error(), "per_tunnel_key")
			if gotErr != tc.wantErr {
				t.Fatalf("per_tunnel_key %q: error=%v, want error=%v (err: %v)",
					tc.value, gotErr, tc.wantErr, err)
			}
		})
	}
}

func TestPerTunnelKeyPhaseAccessor(t *testing.T) {
	e := validExit()
	if got := e.PerTunnelKeyPhase(); got != domain.PerTunnelKeyOff {
		t.Fatalf("unset phase = %q, want %q", got, domain.PerTunnelKeyOff)
	}
	e.PerTunnelKey = "switch"
	if got := e.PerTunnelKeyPhase(); got != domain.PerTunnelKeySwitch {
		t.Fatalf("phase = %q, want %q", got, domain.PerTunnelKeySwitch)
	}
}

func TestPerTunnelKeyPhaseSideMovement(t *testing.T) {
	// Each transition must move exactly ONE side of the tunnel — that property is
	// what makes every step individually rollback-safe.
	type sides struct{ masterNew, exitLegacy, exitNew bool }
	got := func(p domain.PerTunnelKeyPhase) sides {
		return sides{p.MasterUsesPerTunnelKey(), p.ExitAcceptsLegacyKey(), p.ExitAcceptsPerTunnelKey()}
	}
	order := []domain.PerTunnelKeyPhase{
		domain.PerTunnelKeyOff, domain.PerTunnelKeyDual,
		domain.PerTunnelKeySwitch, domain.PerTunnelKeyOn,
	}
	for i := 1; i < len(order); i++ {
		prev, cur := got(order[i-1]), got(order[i])
		changed := 0
		if prev.masterNew != cur.masterNew {
			changed++
		}
		if prev.exitLegacy != cur.exitLegacy {
			changed++
		}
		if prev.exitNew != cur.exitNew {
			changed++
		}
		if changed != 1 {
			t.Fatalf("%s→%s changes %d things, want exactly 1 (%+v → %+v)",
				order[i-1], order[i], changed, prev, cur)
		}
	}
	// And there must always be at least one peer the master can reach the exit by.
	for _, p := range order {
		s := got(p)
		if !s.exitLegacy && !s.exitNew {
			t.Fatalf("phase %s leaves the exit with no master peer at all", p)
		}
		if s.masterNew && !s.exitNew {
			t.Fatalf("phase %s dials with the per-tunnel key the exit does not accept", p)
		}
		if !s.masterNew && !s.exitLegacy {
			t.Fatalf("phase %s dials with the shared key the exit no longer accepts", p)
		}
	}
}
