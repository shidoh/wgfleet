package wg

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Under Track B the QUIC cover (I2) must be keyed off the fleet secret, so its
// bytes cannot be reproduced from the public salt and a node name alone. Same
// tunnel seed + different secret => different cover; same secret => stable; and
// the cover still parses as a valid client Initial.
func TestTrackBPrologueSeedUsesSecret(t *testing.T) {
	const seed = "exit-de-1|master-1|wgfleet-awg-v1"
	base := func() domain.AWGParams { return DeriveAWGParamsForEnd(seed, "exit", true) }

	a := WithAWG3(base(), seed, "fleet-secret-A").Local.I2
	a2 := WithAWG3(base(), seed, "fleet-secret-A").Local.I2
	b := WithAWG3(base(), seed, "fleet-secret-B").Local.I2
	pub := DeriveAWGLocal(seed, true).I2 // public-salt cover, pre-Track-B

	if a == "" || !strings.HasPrefix(a, "<b 0x") {
		t.Fatalf("I2 not rendered: %.40q", a)
	}
	if a != a2 {
		t.Error("same secret must give a stable cover (idempotent reconcile)")
	}
	if a == b {
		t.Error("different fleet secrets must give different covers")
	}
	if a == pub {
		t.Error("Track B cover must differ from the public-salt cover (secret-keying had no effect)")
	}
	// Still a real, decryptable Chrome Initial with a server name and h3.
	got := openClientInitial(t, decodeStaticTemplate(t, a))
	if got.alpn != "h3" || got.sni == "" {
		t.Errorf("secret-keyed cover is not a valid Initial: sni=%q alpn=%q", got.sni, got.alpn)
	}
}
