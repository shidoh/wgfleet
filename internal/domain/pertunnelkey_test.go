package domain

import "testing"

func TestMasterTunnelHostIndex(t *testing.T) {
	cases := []struct{ slot, legacy, perTunnel int }{
		{0, 2, 3}, // today's addressing: must never move
		{1, 4, 5},
		{2, 6, 7},
	}
	for _, c := range cases {
		legacy, perTunnel := MasterTunnelHostIndex(c.slot)
		if legacy != c.legacy || perTunnel != c.perTunnel {
			t.Errorf("slot %d: got (%d,%d), want (%d,%d)", c.slot, legacy, perTunnel, c.legacy, c.perTunnel)
		}
	}
	// No two slots may ever share a host: a shared /32 is silently stolen.
	seen := map[int]int{}
	for s := 0; s <= MaxMasterSlot; s++ {
		legacy, perTunnel := MasterTunnelHostIndex(s)
		for _, h := range []int{legacy, perTunnel} {
			if prev, dup := seen[h]; dup {
				t.Fatalf("host %d given to slots %d and %d", h, prev, s)
			}
			seen[h] = s
		}
	}
}
