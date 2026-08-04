package egress

import (
	"slices"
	"strconv"
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

// The probe must cap the hop count. tracepath decides it has arrived when the
// destination answers ICMP port-unreachable; Cloudflare's anycast edge never does,
// and stops answering at all a few hops in, so an uncapped run walks its full
// 30-hop default at roughly a second per silent hop. That overruns the caller's
// 30s deadline, and the SIGKILL discards tracepath's block-buffered stdout, so the
// salvage path in ProbeWARPMTU never sees the partial output it was written for —
// auto-MTU discovery failed on every exit in the fleet.
func TestTracepathArgsCapsHops(t *testing.T) {
	args := tracepathArgs("engage.cloudflareclient.com")
	i := slices.Index(args, "-m")
	if i < 0 || i == len(args)-1 {
		t.Fatalf("tracepath args %q do not cap the hop count (-m)", args)
	}
	n, err := strconv.Atoi(args[i+1])
	if err != nil {
		t.Fatalf("hop cap %q is not a number (args %q)", args[i+1], args)
	}
	// Measured 2026-08-04 on three exits: capped at 10 hops tracepath exits 0 in
	// 9-16s and prints "Resume: pmtu N". The bound keeps a later bump from silently
	// walking back past the 30s deadline this cap exists to fit inside.
	if n <= 0 || n > 15 {
		t.Errorf("hop cap = %d, want a small positive cap that fits the probe deadline", n)
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
