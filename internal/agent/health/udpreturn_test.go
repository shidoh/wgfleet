package health

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The check must fail ONLY on the dangerous combination: a port whose replies
// cannot come back AND which nothing has decided about. A blocked-but-accepted
// port is the fixed state; a bindable port is fine; and a probe that could not be
// taken must say so rather than report green.
func TestClientUDPReturnProbeFailsOnlyOnUndeclaredBlackHoles(t *testing.T) {
	blocked := func(p int) (bool, error) { return p != 443, nil }

	t.Run("blocked and accepted passes", func(t *testing.T) {
		r := ClientUDPReturnProbe([]int{443, 51820}, blocked, func(p int) bool { return p == 443 })(context.Background())
		if !r.OK {
			t.Errorf("a blocked-but-accepted port must pass; got %q", r.Detail)
		}
	})

	t.Run("blocked and undeclared fails and names the port", func(t *testing.T) {
		r := ClientUDPReturnProbe([]int{443}, blocked, func(int) bool { return false })(context.Background())
		if r.OK {
			t.Fatal("a blocked and undeclared port is a silent black hole and must fail the check")
		}
		if !strings.Contains(r.Detail, "443") {
			t.Errorf("the failure does not name the port, so nobody can act on it: %q", r.Detail)
		}
	})

	t.Run("nothing blocked passes", func(t *testing.T) {
		r := ClientUDPReturnProbe([]int{51820, 9993}, blocked, func(int) bool { return false })(context.Background())
		if !r.OK {
			t.Errorf("no black holes, yet the check failed: %q", r.Detail)
		}
	})

	// Being unable to LOOK is not the same as the path being broken, and it is also
	// not the same as it being fine. Reporting green on a blind probe is how a
	// non-Linux build, or a run without CAP_NET_ADMIN, would vouch for a node it
	// never examined.
	t.Run("blind probe fails loudly rather than passing", func(t *testing.T) {
		blind := func(int) (bool, error) { return false, errors.New("no CAP_NET_ADMIN") }
		r := ClientUDPReturnProbe([]int{443}, blind, func(int) bool { return false })(context.Background())
		if r.OK {
			t.Fatal("a probe that could not be taken reported the node healthy")
		}
		if !strings.Contains(r.Detail, "could not check") {
			t.Errorf("the failure reads like an outage rather than blindness: %q", r.Detail)
		}
	})

	// A blocked port that is accepted must not be reported even when a DIFFERENT
	// port is blind: the two conditions are independent and both belong in the text.
	t.Run("ports with no socket are skipped", func(t *testing.T) {
		r := ClientUDPReturnProbe([]int{0, -1}, blocked, func(int) bool { return false })(context.Background())
		if !r.OK {
			t.Errorf("meaningless ports were probed instead of skipped: %q", r.Detail)
		}
	})
}

// The port list must come from the kernel, not from a list in the code. This is
// the parser for /proc/net/udp; the format is stable and the local address column
// is `<hex address>:<hex port>`.
func TestParseHeldUDPPortsReadsTheKernelTable(t *testing.T) {
	// Real shape, trimmed: wg0 on 443 (0x01BB) bound wildcard, ZeroTier on 9993
	// (0x2709) bound to a specific address, and a high ephemeral port.
	const proc = `  sl  local_address rem_address   st tx_queue rx_queue tr tx_when retrnsmt   uid  timeout inode ref pointer drops
 2110: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000000000000000 0
 2111: 0100460A:2709 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12346 2 0000000000000000 0
 2112: 00000000:C4CF 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12347 2 0000000000000000 0
`
	got, err := parseHeldUDPPorts(strings.NewReader(proc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[int]bool{443: true, 9993: true, 50383: true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want the three ports %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected port %d in %v", p, got)
		}
	}
}

// The header row and anything unparseable must be skipped rather than turned into
// a bogus port — a bogus port becomes a bogus black hole and a false Degraded.
func TestParseHeldUDPPortsSkipsJunk(t *testing.T) {
	got, err := parseHeldUDPPorts(strings.NewReader("  sl  local_address rem_address\nnonsense\n 1: notahex:notaport x\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("junk produced ports: %v", got)
	}
}

// A node whose client interface is NOT on 443 must not be told it has a black
// hole. This is the upgrade path for every other fleet: they swap the binary, the
// probe runs, and the port their own interface holds has to be recognised as
// theirs. An earlier version listed 443 in source and would have driven any such
// node to Degraded on its first pass after the upgrade — the same mistake as the
// bug it was written to catch.
func TestClientUDPReturnProbeAcceptsWhateverPortThisNodeHolds(t *testing.T) {
	// This node's client interface is on 51820, not 443.
	const ours = 51820
	blocked := func(p int) (bool, error) { return p != ours, nil }
	accepted := func(p int) bool { return p == ours }

	r := ClientUDPReturnProbe([]int{ours, 443, 4433}, blocked, accepted)(context.Background())
	if !r.OK {
		t.Errorf("a node on port %d was reported broken: %q", ours, r.Detail)
	}
}
