package egress

import (
	"slices"
	"testing"
)

// The probe must pin IPv4: the WARP endpoint resolves AAAA-first, and a v6 probe
// black-holes on the IPv4-only data plane until the caller's timeout kills it,
// which disabled auto-MTU discovery fleet-wide.
func TestTracepathArgsForceIPv4(t *testing.T) {
	args := tracepathArgs("engage.cloudflareclient.com")
	if !slices.Contains(args, "-4") {
		t.Errorf("tracepath args %q do not force IPv4 (-4)", args)
	}
	if got := args[len(args)-1]; got != "engage.cloudflareclient.com" {
		t.Errorf("host = %q, want it last in %q", got, args)
	}
}

func TestLastPMTU(t *testing.T) {
	out := ` 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                              0.5ms
 2:  no reply
 3:  162.159.192.1                        12ms pmtu 1440
     resume: pmtu 1440`
	if got := lastPMTU(out); got != 1440 {
		t.Errorf("lastPMTU = %d, want 1440", got)
	}
	if got := lastPMTU("no pmtu here"); got != 0 {
		t.Errorf("lastPMTU(none) = %d, want 0", got)
	}
}
