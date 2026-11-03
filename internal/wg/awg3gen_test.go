package wg

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// testAWG3Key stands in for fleet.awg3_key. Its value is irrelevant to these
// tests; what matters is that deriving header protection now REQUIRES a secret,
// which is the change they were updated for.
const testAWG3Key = "test-fleet-awg3-secret"

// splitRange parses "N" or "min-max" into its bounds, failing the test on junk.
func splitRange(t *testing.T, v string) (lo, hi int) {
	t.Helper()
	l, h, isRange := strings.Cut(v, "-")
	lo, err := strconv.Atoi(l)
	if err != nil {
		t.Fatalf("bad range %q: %v", v, err)
	}
	if !isRange {
		return lo, lo
	}
	hi, err = strconv.Atoi(h)
	if err != nil {
		t.Fatalf("bad range %q: %v", v, err)
	}
	return lo, hi
}

// TestWithAWG3Deterministic — both ends of a tunnel derive the 3.0 block from the
// SAME tunnel seed with no coordination, exactly like S1-S4/H1-H4. If this ever
// stopped being a pure function of the seed the two ends would disagree on the
// header-protection key and the tunnel would silently never handshake.
func TestWithAWG3Deterministic(t *testing.T) {
	a := WithAWG3(DeriveAWGParamsForEnd("seed-a", "master", false), "seed-a", testAWG3Key)
	b := WithAWG3(DeriveAWGParamsForEnd("seed-a", "exit", true), "seed-a", testAWG3Key)
	if a.Shared != b.Shared {
		t.Errorf("shared block must be identical across ends:\n%+v\n%+v", a.Shared, b.Shared)
	}
	c := WithAWG3(DeriveAWGParamsForEnd("seed-b", "master", false), "seed-b", testAWG3Key)
	if c.Shared.HeaderProtectionKey == a.Shared.HeaderProtectionKey {
		t.Error("different tunnel seeds must yield different header-protection keys")
	}
}

// TestWithAWG3KeyIs32Bytes — the module's key is a chacha20 key; anything else is
// rejected by setconf on the node.
func TestWithAWG3KeyIs32Bytes(t *testing.T) {
	p := WithAWG3(DeriveAWGParamsForEnd("seed", "master", false), "seed", testAWG3Key)
	raw, err := base64.StdEncoding.DecodeString(p.Shared.HeaderProtectionKey)
	if err != nil {
		t.Fatalf("key must be base64: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("key decodes to %d bytes, want 32", len(raw))
	}
}

// TestWithAWG3AlwaysValidates is the real guard: whatever the seed, the derived
// block must satisfy every domain rule — above all the S1-S4 >= 12 floor that
// header protection imposes and that the kernel accepts silently when violated.
// Sweeping many seeds because the S values are themselves derived.
func TestWithAWG3AlwaysValidates(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		p := WithAWG3(DeriveAWGParamsForEnd(seed, "master", false), seed, testAWG3Key)
		if err := p.Validate(); err != nil {
			t.Fatalf("seed %q derived an invalid AWG 3.0 param set: %v\n%+v", seed, err, p.Shared)
		}
		for _, s := range []struct {
			n string
			v int
		}{{"S1", p.Shared.S1}, {"S2", p.Shared.S2}, {"S3", p.Shared.S3}, {"S4", p.Shared.S4}} {
			if s.v < 12 {
				t.Fatalf("seed %q: %s = %d < 12, header protection would break the tunnel", seed, s.n, s.v)
			}
		}
	}
}

// TestWithAWG3TimerOrdering — rekey must always begin before the session is
// rejected. RejectAfterTime is never set, so the bound is the WireGuard default;
// the randomised rekey must stay below it, and below the receive-side refresh
// threshold (Reject − Keepalive − RekeyTimeout), for every seed.
func TestWithAWG3TimerOrdering(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		s := WithAWG3(DeriveAWGParamsForEnd(seed, "master", false), seed, testAWG3Key).Shared
		if s.RejectAfterTime != "" {
			t.Fatalf("seed %q: RejectAfterTime = %q, must stay at the default", seed, s.RejectAfterTime)
		}
		_, rekeyHi := splitRange(t, s.RekeyAfterTime)
		_, keepaliveHi := splitRange(t, s.KeepaliveTimeout)
		refresh := defaultRejectAfterTime - keepaliveHi - defaultRekeyTimeout
		if rekeyHi >= refresh || rekeyHi >= defaultRejectAfterTime {
			t.Fatalf("seed %q: RekeyAfterTime %q reaches the refresh threshold %ds (KeepaliveTimeout %q) or the %ds reject",
				seed, s.RekeyAfterTime, refresh, s.KeepaliveTimeout, defaultRejectAfterTime)
		}
	}
}

// TestWithAWG3TimerSet — exactly two timers are randomised, the others stay at
// the defaults because kernel and Go implementations disagree on them. A scalar
// timer would be a timing fingerprint, so the two that are set must be ranges
// starting at the WireGuard default.
func TestWithAWG3TimerSet(t *testing.T) {
	for i := 0; i < 200; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		s := WithAWG3(DeriveAWGParamsForEnd(seed, "master", false), seed, testAWG3Key).Shared
		for _, f := range []struct {
			name, value      string
			lo, hiMin, hiMax int
		}{
			{"RekeyAfterTime", s.RekeyAfterTime, 120, 130, 140},
			{"KeepaliveTimeout", s.KeepaliveTimeout, 10, 12, 15},
		} {
			lo, hi := splitRange(t, f.value)
			if lo != f.lo || hi < f.hiMin || hi > f.hiMax {
				t.Fatalf("seed %q: %s = %q, want %d-[%d..%d]", seed, f.name, f.value, f.lo, f.hiMin, f.hiMax)
			}
		}
		for _, f := range []struct{ name, value string }{
			{"RekeyTimeout", s.RekeyTimeout},
			{"RejectAfterTime", s.RejectAfterTime},
			{"MaxHandshakeAttempts", s.MaxHandshakeAttempts},
		} {
			if f.value != "" {
				t.Fatalf("seed %q: %s = %q, must stay unset (WireGuard default)", seed, f.name, f.value)
			}
		}
	}
}

// TestWithAWG3LeavesContentPaddingUnset is a deliberate, load-bearing omission.
// ContentPaddingAddition rides on EVERY data packet the way S4 does, so deriving a
// non-zero value would silently eat the MTU cushion that AWGExtraOverhead sizes
// and black-hole full-size packets. Enabling it means folding it into
// the MTU chain first.
func TestWithAWG3LeavesContentPaddingUnset(t *testing.T) {
	s := WithAWG3(DeriveAWGParamsForEnd("seed", "master", false), "seed", testAWG3Key).Shared
	if s.ContentPaddingAddition != "" {
		t.Errorf("ContentPaddingAddition must stay unset until it is part of the MTU computation, got %q", s.ContentPaddingAddition)
	}
}

// TestWithAWG3PreservesAWG2 — the 3.0 block is additive; nothing about the 2.0
// params may shift, or an in-place upgrade would rewrite every interface.
// Header protection brings Track B with it: random trailers, one padding size for
// all four message types (upstream 3.1: with trailers, unequal S makes the
// receiver drop transport packets — amneziawg-go #186), the stock header types,
// and a junk window moved by exactly the change in S4.
func TestWithAWG3HeaderProtectionIsTrackB(t *testing.T) {
	for i := 0; i < 300; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		base := DeriveAWGParamsForEnd(seed, "master", false)
		got := WithAWG3(base, seed, testAWG3Key)
		s := got.Shared
		if !s.RandomTrailers || s.HeaderProtectionKey == "" {
			t.Fatalf("seed %q: trailers %v, key %q", seed, s.RandomTrailers, s.HeaderProtectionKey)
		}
		if s.S1 != s.S2 || s.S2 != s.S3 || s.S3 != s.S4 || s.S1 < 12 || s.S1 > 31 || s.S1 == 16 {
			t.Fatalf("seed %q: S = %d/%d/%d/%d, want one value in [12,31] other than 16", seed, s.S1, s.S2, s.S3, s.S4)
		}
		for j, h := range []domain.AWGHeader{s.H1, s.H2, s.H3, s.H4} {
			if h.Min != uint32(j+1) || h.Max != uint32(j+1) {
				t.Fatalf("seed %q: H%d = %v, want %d", seed, j+1, h, j+1)
			}
		}
		if d := got.Local.Jmin - base.Local.Jmin; d != s.S4-base.Shared.S4 || got.Local.Jmax-base.Local.Jmax != d {
			t.Fatalf("seed %q: junk window moved by %d, S4 by %d", seed, d, s.S4-base.Shared.S4)
		}
		if got.Local.I1 != base.Local.I1 || got.Local.Jc != base.Local.Jc {
			t.Fatalf("seed %q: the decoy changed beyond the junk window", seed)
		}
		if err := got.ValidateUserspace(); err != nil {
			t.Fatalf("seed %q: %v", seed, err)
		}
	}
	if base := DeriveAWGParamsForEnd("seed", "master", false); base.AWG3Enabled() {
		t.Error("the base derivation must stay pure AWG 2.0")
	}
}

// The padding comes from the fleet secret: under Track B it is the one size every
// message carries, and it must not be computable from a node name.
func TestTrackBPaddingDependsOnTheSecret(t *testing.T) {
	differs := 0
	for i := 0; i < 50; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		if deriveTrackBPadding(seed, "secret-a") != deriveTrackBPadding(seed, "secret-b") {
			differs++
		}
	}
	if differs < 30 {
		t.Errorf("padding differs between secrets for only %d of 50 tunnels", differs)
	}
}

// The timers-only half is the one an operator can switch on WITHOUT reissuing a
// single client config: measured against a real 3.1 kernel module, an untouched
// AmneziaWG 2.0 peer keeps handshaking and passing traffic across rekeys when the
// server randomises its timers. HeaderProtectionKey is what breaks that peer, so
// this half must never set it — that absence IS the compatibility guarantee.
func TestWithAWG3TimersLeavesHeaderProtectionUnset(t *testing.T) {
	for i := 0; i < 200; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		s := WithAWG3Timers(DeriveAWGParamsForEnd(seed, "client", false), seed).Shared
		if s.HeaderProtectionKey != "" {
			t.Fatalf("seed %q: timers-only set a HeaderProtectionKey, which cuts off every 2.0 client", seed)
		}
		if s.RekeyAfterTime == "" || s.KeepaliveTimeout == "" {
			t.Fatalf("seed %q: timers-only left the timers unset: %+v", seed, s)
		}
	}
}

// The other half on its own, so the two compose rather than overlap.
func TestWithAWG3HeaderProtectionLeavesTimersUnset(t *testing.T) {
	seed := "tunnel-hp"
	s := WithAWG3HeaderProtection(DeriveAWGParamsForEnd(seed, "client", false), seed, testAWG3Key).Shared
	if s.HeaderProtectionKey == "" {
		t.Fatal("header-protection half set no key")
	}
	if s.RekeyAfterTime != "" || s.RejectAfterTime != "" || s.KeepaliveTimeout != "" ||
		s.RekeyTimeout != "" || s.MaxHandshakeAttempts != "" {
		t.Fatalf("header-protection half also set timers: %+v", s)
	}
}

// WithAWG3 must stay exactly the sum of its halves. The master↔exit leg still
// calls it and both ends of that tunnel derive independently — a change in what
// it produces is a change both ends must make in the same release or the
// handshake stops completing.
func TestWithAWG3IsBothHalvesComposed(t *testing.T) {
	for i := 0; i < 200; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		base := DeriveAWGParamsForEnd(seed, "exit", true)
		whole := WithAWG3(base, seed, testAWG3Key)
		composed := WithAWG3HeaderProtection(WithAWG3Timers(base, seed), seed, testAWG3Key)
		if whole.Shared != composed.Shared {
			t.Fatalf("seed %q: WithAWG3 diverged from its halves\n whole:    %+v\n composed: %+v",
				seed, whole.Shared, composed.Shared)
		}
	}
}

// A timers-only set carries no header protection, so it must NOT inherit the
// S1-S4 >= 12 floor that header protection imposes. Enforcing it anyway would
// refuse perfectly good configs on the one path that exists to avoid a flag day.
func TestWithAWG3TimersValidateWithSmallPadding(t *testing.T) {
	p := WithAWG3Timers(DeriveAWGParamsForEnd("small-s", "client", false), "small-s")
	p.Shared.S1, p.Shared.S2, p.Shared.S3, p.Shared.S4 = 1, 2, 3, 4
	if err := p.Validate(); err != nil {
		t.Fatalf("timers-only params rejected for small S values: %v", err)
	}
}

// The header-protection key must depend on the fleet secret, and depend on it
// strongly: the same tunnel under two secrets must yield two unrelated keys.
func TestHeaderProtectionKeyIsKeyedOnTheFleetSecret(t *testing.T) {
	const seed = "master-xa-1|vn0|wgfleet-awg-v1"
	a := deriveHeaderProtectionKey(seed, "secret-one")
	if b := deriveHeaderProtectionKey(seed, "secret-two"); a == b {
		t.Fatal("the key does not depend on the fleet secret at all")
	}
	if again := deriveHeaderProtectionKey(seed, "secret-one"); again != a {
		t.Fatal("the key is not reproducible from the same inputs")
	}
	// It must still vary per tunnel under one secret, or the whole fleet would
	// share a single header-protection key.
	if other := deriveHeaderProtectionKey("master-xa-1|anz3|wgfleet-awg-v1", "secret-one"); other == a {
		t.Fatal("two different tunnels derive the same key")
	}
	// And an empty secret must not be indistinguishable from a real one — that is
	// the state the config gate exists to prevent, and if it is ever reached it
	// should be visible here rather than in the field.
	if deriveHeaderProtectionKey(seed, "") == deriveHeaderProtectionKey(seed, "x") {
		t.Fatal("the empty secret behaves like a configured one")
	}
}
