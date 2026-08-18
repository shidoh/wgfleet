package wg

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func awg3Params() domain.AWGParams {
	return domain.AWGParams{
		Shared: domain.AWGShared{
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
		},
		Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900},
	}
}

func renderWithAWG(t *testing.T, p domain.AWGParams) string {
	t.Helper()
	cfg, err := RenderInterface(RenderInput{
		Spec: domain.WGServerSpec{
			ListenPort: 51820, AddressPool: "10.81.0.0/24", Address: "10.81.0.1", MTU: 1420,
			AWG: &p,
		},
		Peers:      []domain.PeerSpec{{Name: "m", PublicKey: testPubKey(t), AllowedIPs: []string{"10.81.0.2/32"}}},
		PrivateKey: testPrivKey(t),
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return cfg
}

// TestRenderAWG3Keys pins the exact [Interface] key spelling amneziawg-tools
// expects. The tools match keys case-insensitively but the VALUE syntax is not
// forgiving, and a key the tools do not recognise is silently ignored — the
// interface comes up without header protection and nothing says so.
func TestRenderAWG3Keys(t *testing.T) {
	cfg := renderWithAWG(t, awg3Params())
	for _, want := range []string{
		"HeaderProtectionKey = " + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"ContentPaddingAddition = 64",
		"RekeyAfterTime = 120-150",
		"RekeyTimeout = 5",
		"RejectAfterTime = 180-220",
		"KeepaliveTimeout = 10-14",
		"MaxHandshakeAttempts = 18",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q in:\n%s", want, cfg)
		}
	}
	// AWG 3.0 keys belong to [Interface], never [Peer] — same rule as every other
	// AmneziaWG param.
	iface, peer, _ := strings.Cut(cfg, "[Peer]")
	if !strings.Contains(iface, "HeaderProtectionKey") {
		t.Error("HeaderProtectionKey must be in [Interface]")
	}
	if strings.Contains(peer, "HeaderProtectionKey") {
		t.Error("AWG 3.0 keys must never appear in [Peer]")
	}
}

// TestRenderAWG2EmitsNoAWG3Keys is the back-compat guard: an interface with no
// AWG 3.0 params must render byte-for-byte the AWG 2.0 config it did before, so
// rolling this code onto a fleet that has not opted in changes nothing.
func TestRenderAWG2EmitsNoAWG3Keys(t *testing.T) {
	p := awg3Params()
	p.Shared.HeaderProtectionKey = ""
	p.Shared.ContentPaddingAddition = ""
	p.Shared.RekeyAfterTime = ""
	p.Shared.RekeyTimeout = ""
	p.Shared.RejectAfterTime = ""
	p.Shared.KeepaliveTimeout = ""
	p.Shared.MaxHandshakeAttempts = ""

	cfg := renderWithAWG(t, p)
	for _, absent := range []string{
		"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
		"RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
	} {
		if strings.Contains(cfg, absent) {
			t.Errorf("AWG 2.0 config must not mention %q:\n%s", absent, cfg)
		}
	}
}

// TestRenderAWG3PartialEmitsOnlySetKeys — the tools treat an absent key as "not
// configured", which is what we want for a partial 3.0 opt-in (say, randomised
// timers without header protection). Emitting an empty value instead would be a
// parse error on the node.
func TestRenderAWG3PartialEmitsOnlySetKeys(t *testing.T) {
	p := awg3Params()
	p.Shared.HeaderProtectionKey = ""
	p.Shared.ContentPaddingAddition = ""
	cfg := renderWithAWG(t, p)
	if strings.Contains(cfg, "HeaderProtectionKey") || strings.Contains(cfg, "ContentPaddingAddition") {
		t.Errorf("unset 3.0 keys must be omitted entirely:\n%s", cfg)
	}
	if !strings.Contains(cfg, "RekeyAfterTime = 120-150") {
		t.Errorf("set 3.0 keys must still render:\n%s", cfg)
	}
}
