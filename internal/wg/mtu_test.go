package wg

import "testing"

func TestTunnelMTU(t *testing.T) {
	tests := []struct {
		name  string
		outer int
		awg   bool
		ipv6  bool
		want  int
	}{
		{"plain wg ipv4", 1500, false, false, 1440},
		{"awg ipv4", 1500, true, false, 1360},
		{"plain wg ipv6", 1500, false, true, 1420},
		{"awg ipv6", 1500, true, true, 1340},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TunnelMTU(tt.outer, tt.awg, tt.ipv6); got != tt.want {
				t.Errorf("TunnelMTU(%d,%v,%v) = %d, want %d", tt.outer, tt.awg, tt.ipv6, got, tt.want)
			}
		})
	}
}

func TestFleetTunnelMTU(t *testing.T) {
	// Each fleet hop is independent over its own physical link (sequential model,
	// ADR-0014): one layer of overhead off DefaultPhysicalMTU, never accumulating.
	tests := []struct {
		name string
		awg  bool
		ipv6 bool
		want int
	}{
		{"client/master/exit AWG ipv4", true, false, 1360},
		{"master↔exit AWG ipv6", true, true, 1340},
		{"warp vanilla wg ipv4", false, false, 1440},
		{"vanilla wg ipv6", false, true, 1420},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FleetTunnelMTU(tt.awg, tt.ipv6); got != tt.want {
				t.Errorf("FleetTunnelMTU(%v,%v) = %d, want %d", tt.awg, tt.ipv6, got, tt.want)
			}
		})
	}
}

func TestSequentialModelNeverFragments(t *testing.T) {
	// The wgfleet path a client payload traverses: client→master (AWG), then
	// master→exit (AWG), then exit→WARP (vanilla WG). The client interface MTU is
	// the minimum across the hops; it must be <= every downstream hop so a
	// full-size client packet never fragments at egress.
	clientAWG := FleetTunnelMTU(true, false)  // 1360
	masterExit := FleetTunnelMTU(true, false) // 1360
	warp := FleetTunnelMTU(false, false)      // 1440

	client := MinMTU(clientAWG, masterExit, warp)
	if client != 1360 {
		t.Errorf("client MTU = %d, want 1360", client)
	}
	for name, hop := range map[string]int{"master↔exit": masterExit, "warp": warp} {
		if client > hop {
			t.Errorf("client MTU %d exceeds %s hop MTU %d: would fragment", client, name, hop)
		}
	}
}

func TestMinMTU(t *testing.T) {
	if got := MinMTU(1440, 1360, 1340); got != 1340 {
		t.Errorf("MinMTU = %d, want 1340", got)
	}
	if got := MinMTU(); got != 0 {
		t.Errorf("MinMTU() = %d, want 0", got)
	}
}
