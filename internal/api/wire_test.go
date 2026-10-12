package api

import "testing"

func TestCheckWire(t *testing.T) {
	tests := []struct {
		name     string
		agent    uint32
		want     Compatibility
		upgrade  bool
		compatOK bool
	}{
		{"current", WireContractVersion, WireCompatible, false, true},
		{"zero is unknown", 0, WireUnknown, true, false},
		{"above current is too new", WireContractVersion + 1, WireAgentTooNew, false, false},
	}
	// A nonzero version below MinSupportedWire only exists once MinSupportedWire > 1.
	if MinSupportedWire > 1 {
		tests = append(tests, struct {
			name     string
			agent    uint32
			want     Compatibility
			upgrade  bool
			compatOK bool
		}{"below min is too old", MinSupportedWire - 1, WireAgentTooOld, true, false})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckWire(tc.agent)
			if got != tc.want {
				t.Errorf("CheckWire(%d) = %v, want %v", tc.agent, got, tc.want)
			}
			if got.AutoUpgradable() != tc.upgrade {
				t.Errorf("AutoUpgradable() = %v, want %v", got.AutoUpgradable(), tc.upgrade)
			}
			if (got == WireCompatible) != tc.compatOK {
				t.Errorf("compatible = %v, want %v", got == WireCompatible, tc.compatOK)
			}
		})
	}
}

func TestIncompatibilityDetailMentionsRange(t *testing.T) {
	d := IncompatibilityDetail(WireAgentTooOld, 0)
	if d == "" {
		t.Fatal("expected a non-empty detail")
	}
	// The operator needs the served range to understand the skew.
	for _, want := range []string{"agent wire v0", "agent-too-old"} {
		if !contains(d, want) {
			t.Errorf("detail %q missing %q", d, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Guard: the wire version must never drift by accident. Changing it is a
// deliberate act with a rollout consequence, so it takes a deliberate test edit.
func TestWireContractVersionIs13(t *testing.T) {
	if WireContractVersion != 13 {
		t.Fatalf("WireContractVersion = %d, want 13 (bumped for StatusReport.master_peers — an exit's per-master-peer report)", WireContractVersion)
	}
}

// A bump is only worth anything if something reads it. Every version that gates a
// feature must have a named constant, because MinSupportedWire is 1 and therefore
// the bump ALONE refuses nobody: the gate is the named comparison, never the number.
func TestClientIPv6GateIsNamedAndCurrent(t *testing.T) {
	if WireMasterPeers != WireContractVersion {
		t.Errorf("WireMasterPeers = %d but the contract is at %d", WireMasterPeers, WireContractVersion)
	}
	if WireAWGExitInitiated >= WireContractVersion {
		t.Errorf("WireAWGExitInitiated = %d but the contract is at %d; the gate must name the version that introduced the field",
			WireAWGExitInitiated, WireContractVersion)
	}
	if WireLifeline >= WireContractVersion {
		t.Errorf("WireLifeline = %d but the contract is at %d; the gate must name the version that introduced the field",
			WireLifeline, WireContractVersion)
	}
	if WireClientIPv6 >= WireContractVersion {
		t.Errorf("WireClientIPv6 = %d but the contract is at %d; the gate must name the version that introduced the field",
			WireClientIPv6, WireContractVersion)
	}
	if CheckWire(WireClientIPv6-1) == WireAgentTooOld {
		t.Error("MinSupportedWire has moved; re-read whether the named gates are still the thing doing the gating")
	}
}
