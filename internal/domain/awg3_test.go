package domain

import (
	"encoding/base64"
	"strings"
	"testing"
)

// hpKey is a syntactically valid HeaderProtectionKey: base64 of exactly 32 bytes
// (HEADER_PROTECTION_KEY_SIZE = CHACHA_KEY_SIZE in the kernel module).
func hpKey() string { return base64.StdEncoding.EncodeToString(make([]byte, 32)) }

// validAWG3 is validAWG plus a complete, well-formed AWG 3.0 block.
func validAWG3() AWGParams {
	p := validAWG()
	p.Shared.S1, p.Shared.S2, p.Shared.S3, p.Shared.S4 = 102, 67, 143, 38
	p.Shared.HeaderProtectionKey = hpKey()
	p.Shared.ContentPaddingAddition = "64"
	p.Shared.RekeyAfterTime = "120-150"
	p.Shared.RekeyTimeout = "5"
	p.Shared.RejectAfterTime = "180-220"
	p.Shared.KeepaliveTimeout = "10-14"
	p.Shared.MaxHandshakeAttempts = "18"
	return p
}

func TestAWG3ValidBlockPasses(t *testing.T) {
	if err := validAWG3().Validate(); err != nil {
		t.Fatalf("a well-formed AWG 3.0 block must validate, got: %v", err)
	}
}

// TestAWG3AbsentIsUnchanged pins backward compatibility: a pure AWG 2.0 param set
// must keep validating exactly as before, with no AWG 3.0 requirement leaking in.
func TestAWG3AbsentIsUnchanged(t *testing.T) {
	p := validAWG()
	p.Shared.S4 = 3 // below the header-protection floor, but no key ⇒ irrelevant
	if err := p.Validate(); err != nil {
		t.Fatalf("AWG 2.0 params must not be subject to AWG 3.0 rules: %v", err)
	}
	if p.AWG3Enabled() {
		t.Error("AWG3Enabled must be false with no AWG 3.0 field set")
	}
}

// TestAWG3HeaderProtectionRequiresSFloor is an earlier finding. The kernel takes the
// 12-byte header-protection nonce from the START of the Sx padding, so a shorter
// pad makes the two ends derive different nonces and every packet is dropped —
// with the interface UP. The module only rejects S<12 for values arriving in the
// SAME setconf, so a config that sets the key and leaves S alone is accepted
// silently. That makes this OUR check, not the kernel's.
func TestAWG3HeaderProtectionRequiresSFloor(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*AWGShared)
	}{
		{"S1", func(s *AWGShared) { s.S1 = 11 }},
		{"S2", func(s *AWGShared) { s.S2 = 0 }},
		{"S3", func(s *AWGShared) { s.S3 = 11 }},
		{"S4", func(s *AWGShared) { s.S4 = 5 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validAWG3()
			tc.set(&p.Shared)
			err := p.Validate()
			if err == nil {
				t.Fatalf("%s below 12 with a HeaderProtectionKey must fail", tc.name)
			}
			if !strings.Contains(err.Error(), tc.name) || !strings.Contains(err.Error(), "12") {
				t.Errorf("error should name %s and the floor 12, got: %v", tc.name, err)
			}
		})
	}
}

// TestAWG3HeaderProtectionKeyMustBe32Bytes — the module's key is a chacha20 key.
// A wrong length is rejected by setconf, but only once it reaches the node; catch
// it in the controller so a bad manifest never leaves a render half-applied.
func TestAWG3HeaderProtectionKeyMustBe32Bytes(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 33))},
		{"not base64", "!!!! not base64 !!!!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validAWG3()
			p.Shared.HeaderProtectionKey = tc.key
			if err := p.Validate(); err == nil {
				t.Fatal("expected an invalid HeaderProtectionKey to fail")
			} else if !strings.Contains(err.Error(), "HeaderProtectionKey") {
				t.Errorf("error should name the field, got: %v", err)
			}
		})
	}
}

// TestAWG3RangesMustParse covers the u16-range syntax AWG 3.0 introduced for the
// timers: a bare number or "min-max" with min <= max. These are the anti-
// fingerprint knob (the device redraws the value on each timer arm), so a typo
// silently reverting to a fixed timer is exactly what we must not ship.
func TestAWG3RangesMustParse(t *testing.T) {
	for _, tc := range []struct{ field, value string }{
		{"RekeyAfterTime", "150-120"}, // inverted
		{"RekeyTimeout", "abc"},
		{"RejectAfterTime", "10-"},
		{"KeepaliveTimeout", "-10"},
		{"MaxHandshakeAttempts", "1-2-3"},
		{"ContentPaddingAddition", "nope"},
	} {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			p := validAWG3()
			switch tc.field {
			case "RekeyAfterTime":
				p.Shared.RekeyAfterTime = tc.value
			case "RekeyTimeout":
				p.Shared.RekeyTimeout = tc.value
			case "RejectAfterTime":
				p.Shared.RejectAfterTime = tc.value
			case "KeepaliveTimeout":
				p.Shared.KeepaliveTimeout = tc.value
			case "MaxHandshakeAttempts":
				p.Shared.MaxHandshakeAttempts = tc.value
			case "ContentPaddingAddition":
				p.Shared.ContentPaddingAddition = tc.value
			}
			if err := p.Validate(); err == nil {
				t.Fatalf("%s=%q must fail", tc.field, tc.value)
			} else if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error should name %s, got: %v", tc.field, err)
			}
		})
	}
}

// TestAWG3EnabledDetectsAnyField — the flag drives whether the renderers emit the
// v3 block at all (mihomo `version: 3`, the exit's awg-quick keys), so it must
// react to every field, not only the key.
func TestAWG3EnabledDetectsAnyField(t *testing.T) {
	for name, set := range map[string]func(*AWGShared){
		"HeaderProtectionKey":    func(s *AWGShared) { s.HeaderProtectionKey = hpKey() },
		"ContentPaddingAddition": func(s *AWGShared) { s.ContentPaddingAddition = "64" },
		"RekeyAfterTime":         func(s *AWGShared) { s.RekeyAfterTime = "120-150" },
		"RekeyTimeout":           func(s *AWGShared) { s.RekeyTimeout = "5" },
		"RejectAfterTime":        func(s *AWGShared) { s.RejectAfterTime = "180" },
		"KeepaliveTimeout":       func(s *AWGShared) { s.KeepaliveTimeout = "10" },
		"MaxHandshakeAttempts":   func(s *AWGShared) { s.MaxHandshakeAttempts = "18" },
	} {
		t.Run(name, func(t *testing.T) {
			p := validAWG()
			set(&p.Shared)
			if !p.AWG3Enabled() {
				t.Errorf("AWG3Enabled must be true once %s is set", name)
			}
		})
	}
}
