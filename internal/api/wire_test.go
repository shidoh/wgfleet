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
