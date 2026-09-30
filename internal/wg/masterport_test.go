package wg

import (
	"fmt"
	"testing"
)

func TestMasterPortForStaysBelowTheEphemeralRange(t *testing.T) {
	for i := range 2000 {
		p := MasterPortFor("master-xa-1", fmt.Sprintf("exit-%d", i))
		if p < MasterPortLow || p > MasterPortHigh {
			t.Fatalf("MasterPortFor(exit-%d) = %d, want within [%d, %d]", i, p, MasterPortLow, MasterPortHigh)
		}
	}
	// The whole band must sit below the kernel's default ip_local_port_range, or an
	// ordinary outbound socket on the master could take the pinned tuple.
	if MasterPortHigh >= 32768 {
		t.Fatalf("MasterPortHigh = %d overlaps the default ephemeral range (32768+)", MasterPortHigh)
	}
}

func TestMasterPortForIsStableAndPerPair(t *testing.T) {
	a := MasterPortFor("m1", "vn0")
	if b := MasterPortFor("m1", "vn0"); a != b {
		t.Fatalf("MasterPortFor is not stable: %d then %d", a, b)
	}
	// The pair, not the exit alone: a second master must get its own tuple (ADR-0027).
	seen := map[int]bool{}
	for _, m := range []string{"m1", "m2", "m3", "m4"} {
		seen[MasterPortFor(m, "vn0")] = true
	}
	if len(seen) < 3 {
		t.Fatalf("MasterPortFor ignores the master name: %d distinct ports for 4 masters", len(seen))
	}
}
