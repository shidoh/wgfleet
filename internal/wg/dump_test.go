package wg

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseShowDump(t *testing.T) {
	out := strings.Join([]string{
		"PRIV\tPUB\t51820\toff\t4\t40\t70\t0\t0\t1\t2\t3\t4",
		"keyA\t(none)\t203.0.113.1:23456\t10.81.0.3/32,10.81.0.2/32\t1800000000\t10\t20\t23",
		"keyB\t(none)\t(none)\t(none)\t0\t0\t0\toff",
		"short\tline",
	}, "\n") + "\n"
	got := ParseShowDump(out)
	if len(got) != 2 {
		t.Fatalf("peers = %+v, want two (the interface line and the short line are not peers)", got)
	}
	a := got[0]
	if a.PublicKey != "keyA" || a.Endpoint != "203.0.113.1:23456" || a.Keepalive != 23 ||
		!a.LatestHandshake.Equal(time.Unix(1_800_000_000, 0)) ||
		!slices.Equal(a.AllowedIPs, []string{"10.81.0.2/32", "10.81.0.3/32"}) {
		t.Errorf("first peer = %+v", a)
	}
	b := got[1]
	if b.PublicKey != "keyB" || b.Endpoint != "" || len(b.AllowedIPs) != 0 || b.Keepalive != 0 || !b.LatestHandshake.IsZero() {
		t.Errorf("second peer = %+v, want a bare key: (none) and off are absences, not values", b)
	}
}

func TestParseShowDumpOfAnInterfaceWithoutPeers(t *testing.T) {
	if got := ParseShowDump("PRIV\tPUB\t51820\toff\n"); len(got) != 0 {
		t.Errorf("peers = %+v, want none", got)
	}
}
