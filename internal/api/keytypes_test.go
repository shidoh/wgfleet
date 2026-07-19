package api

import "testing"

func TestParseTunnelKeyType(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		wantTunnel string
		wantOK     bool
	}{
		{"per-tunnel key", "wireguard:anz3", "anz3", true},
		{"exit name with a dash", "wireguard:exit-de-1", "exit-de-1", true},
		// The shared identity must never be mistaken for a per-tunnel one.
		{"shared wireguard key", KeyTypeWireGuard, "", false},
		{"reality key", KeyTypeReality, "", false},
		// A bare prefix carries no tunnel and would otherwise store a key under "".
		{"bare prefix", "wireguard:", "", false},
		{"unrelated type", "ssh", "", false},
		{"prefix not at the start", "x-wireguard:anz3", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tunnel, ok := ParseTunnelKeyType(tc.keyType)
			if ok != tc.wantOK || tunnel != tc.wantTunnel {
				t.Fatalf("ParseTunnelKeyType(%q) = (%q, %v), want (%q, %v)",
					tc.keyType, tunnel, ok, tc.wantTunnel, tc.wantOK)
			}
		})
	}
}

func TestTunnelKeyTypeRoundTrips(t *testing.T) {
	for _, tunnel := range []string{"anz3", "1cnode004", "pn8", "vn1", "vn2"} {
		got, ok := ParseTunnelKeyType(TunnelKeyType(tunnel))
		if !ok || got != tunnel {
			t.Fatalf("round-trip of %q gave (%q, %v)", tunnel, got, ok)
		}
	}
}
