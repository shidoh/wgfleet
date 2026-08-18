package config

import "testing"

// TestAWG3ForDefaultsOff — unlike the hardening knobs next door, AmneziaWG 3.0 is
// OPT-IN. The fail-safe direction is inverted here: an unconfigured fleet must
// keep speaking the 2.0 its nodes already run, because turning 3.0 on requires a
// 3.x kernel module on the exit and a wire-v7 agent. "Forgot to configure it"
// must never mean "quietly changed the wire format".
func TestAWG3ForDefaultsOff(t *testing.T) {
	var f FleetSection
	if f.AWG3For(ExitConfig{}) {
		t.Error("AWG 3.0 must default to off")
	}
}

func TestAWG3ForPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fleet *bool
		node  *bool
		want  bool
	}{
		{"both unset", nil, nil, false},
		{"fleet on", ptr(true), nil, true},
		{"fleet off", ptr(false), nil, false},
		{"node on beats fleet off", ptr(false), ptr(true), true},
		{"node off beats fleet on", ptr(true), ptr(false), false},
		{"node on, fleet unset", nil, ptr(true), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := FleetSection{AWG3: tc.fleet}
			if got := f.AWG3For(ExitConfig{AWG3: tc.node}); got != tc.want {
				t.Errorf("AWG3For = %v, want %v", got, tc.want)
			}
		})
	}
}
