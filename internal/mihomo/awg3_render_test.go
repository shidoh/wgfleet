package mihomo

import (
	"encoding/base64"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func awg3Shared() domain.AWGShared {
	return domain.AWGShared{
		H1: domain.AWGHeader{Min: 15384729, Max: 145384729},
		H2: domain.AWGHeader{Min: 412847193, Max: 542847193},
		H3: domain.AWGHeader{Min: 983471628, Max: 1113471628},
		H4: domain.AWGHeader{Min: 1524719384, Max: 1654719384},
		S1: 102, S2: 67, S3: 143, S4: 38,

		HeaderProtectionKey:    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ContentPaddingAddition: "64",
		RekeyAfterTime:         "120-150",
		RekeyTimeout:           "5",
		RejectAfterTime:        "180-220",
		KeepaliveTimeout:       "10-14",
		MaxHandshakeAttempts:   "18",
	}
}

// TestAWGOptionEmitsVersion3 is the load-bearing half of the whole AWG 3.0
// plumbing on the master side. mihomo picks the implementation off `version`:
// only the literal 3 selects the v3 device, every other value (including an
// ABSENT key) falls through to the legacy one — which would ignore the v3 keys
// and leave the master speaking 2.0 at an exit already speaking 3.0.
func TestAWGOptionEmitsVersion3(t *testing.T) {
	opt := awgOption(domain.AWGParams{
		Shared: awg3Shared(),
		Local:  domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900},
	})
	if opt["version"] != 3 {
		t.Fatalf("version = %v (%T), want int 3", opt["version"], opt["version"])
	}
	for k, want := range map[string]string{
		"header-protection-key":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"content-padding-addition": "64",
		"rekey-after-time":         "120-150",
		"rekey-timeout":            "5",
		"reject-after-time":        "180-220",
		"keepalive-timeout":        "10-14",
		"max-handshake-attempts":   "18",
	} {
		if opt[k] != want {
			t.Errorf("%s = %v, want %q", k, opt[k], want)
		}
	}
}

// TestAWGOptionAWG2OmitsVersion pins back-compat: without 3.0 params the option
// block must be exactly what it was, `version` included — an explicit `version: 0`
// would be harmless to mihomo but would churn every existing config and force a
// container restart across the fleet for no behaviour change.
func TestAWGOptionAWG2OmitsVersion(t *testing.T) {
	opt := awgOption(domain.AWGParams{
		Shared: domain.AWGShared{S1: 102, S2: 67, S3: 143, S4: 38},
		Local:  domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900},
	})
	if _, ok := opt["version"]; ok {
		t.Errorf("AWG 2.0 params must not emit a version key, got %v", opt["version"])
	}
	for _, k := range []string{
		"header-protection-key", "content-padding-addition", "rekey-after-time",
		"rekey-timeout", "reject-after-time", "keepalive-timeout", "max-handshake-attempts",
	} {
		if _, ok := opt[k]; ok {
			t.Errorf("AWG 2.0 params must not emit %q", k)
		}
	}
}

// TestAWGOptionPartialAWG3StillVersion3 — any 3.0 field at all selects the v3
// device, because the legacy implementation would silently drop that field.
func TestAWGOptionPartialAWG3StillVersion3(t *testing.T) {
	s := domain.AWGShared{S1: 102, S2: 67, S3: 143, S4: 38, RekeyAfterTime: "120-150"}
	opt := awgOption(domain.AWGParams{Shared: s, Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900}})
	if opt["version"] != 3 {
		t.Fatalf("a single 3.0 field must still select version 3, got %v", opt["version"])
	}
	if _, ok := opt["header-protection-key"]; ok {
		t.Error("unset 3.0 keys must be omitted, not emitted empty")
	}
}
