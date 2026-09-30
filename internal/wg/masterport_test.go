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
	a := MasterPortFor("m1", "exit-a")
	if b := MasterPortFor("m1", "exit-a"); a != b {
		t.Fatalf("MasterPortFor is not stable: %d then %d", a, b)
	}
	// The pair, not the exit alone: a second master must get its own tuple (ADR-0027).
	seen := map[int]bool{}
	for _, m := range []string{"m1", "m2", "m3", "m4"} {
		seen[MasterPortFor(m, "exit-a")] = true
	}
	if len(seen) < 3 {
		t.Fatalf("MasterPortFor ignores the master name: %d distinct ports for 4 masters", len(seen))
	}
}

// Generation 0 is the port a tunnel already has; a rotation must not move a
// tunnel that never rotated, and each later generation must land somewhere new.
func TestMasterPortForGen(t *testing.T) {
	if MasterPortForGen("m", "exit-a", 0) != MasterPortFor("m", "exit-a") {
		t.Fatal("generation 0 moved an existing tunnel's port")
	}
	seen := map[int]bool{MasterPortFor("m", "exit-a"): true}
	for gen := 1; gen <= 5; gen++ {
		p := MasterPortForGen("m", "exit-a", gen)
		if p < MasterPortLow || p > MasterPortHigh {
			t.Fatalf("gen %d port %d out of band", gen, p)
		}
		seen[p] = true
	}
	if len(seen) < 5 {
		t.Fatalf("rotations reuse ports: %d distinct over 6 generations", len(seen))
	}
}

func TestExitInitiatedKeepaliveFor(t *testing.T) {
	for i := range 500 {
		k := ExitInitiatedKeepaliveFor(fmt.Sprintf("exit-%d", i))
		if k < 5 || k > 9 {
			t.Fatalf("keepalive %d outside 5-9 s", k)
		}
	}
}
