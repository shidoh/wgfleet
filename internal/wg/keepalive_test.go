package wg

import (
	"fmt"
	"testing"
)

// Every tunnel in the fleet used a hardcoded 25-second keepalive, on every leg:
// the client's config, the master's mihomo proxies and the exit's peer entry. An
// idle tunnel therefore emitted a constant-size datagram on a period identical
// across the whole fleet — the strongest single fingerprint in the system, and one
// that survives every payload obfuscation we apply.
func TestKeepaliveForSpreadsWithinTheNATSafeBand(t *testing.T) {
	seen := make(map[int]int)
	for i := 0; i < 2000; i++ {
		got := KeepaliveFor(fmt.Sprintf("tunnel-%d", i))
		if got < keepaliveLowSeconds || got > keepaliveHighSeconds {
			t.Fatalf("KeepaliveFor(%d) = %d, outside [%d,%d]", i, got, keepaliveLowSeconds, keepaliveHighSeconds)
		}
		if got >= 30 {
			t.Fatalf("KeepaliveFor(%d) = %d, at or above the ~30s consumer-NAT mapping timeout", i, got)
		}
		seen[got]++
	}
	if want := keepaliveHighSeconds - keepaliveLowSeconds + 1; len(seen) != want {
		t.Errorf("%d distinct periods across 2000 ends, want all %d in the band", len(seen), want)
	}
	// No single period may dominate — that would just move the fleet-wide constant.
	for v, n := range seen {
		if share := float64(n) / 2000; share > 0.20 {
			t.Errorf("period %d takes %.0f%% of ends; the fleet still shares one beacon", v, share*100)
		}
	}
}

func TestKeepaliveForIsStable(t *testing.T) {
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("client-%d", i)
		if a, b := KeepaliveFor(id), KeepaliveFor(id); a != b {
			t.Fatalf("KeepaliveFor(%q) = %d then %d; a re-rendered config would change under the user", id, a, b)
		}
	}
}
