package wg

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

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
	a := WithAWG3(DeriveAWGParamsForEnd("seed-a", "master", false), "seed-a")
	b := WithAWG3(DeriveAWGParamsForEnd("seed-a", "exit", true), "seed-a")
	if a.Shared != b.Shared {
		t.Errorf("shared block must be identical across ends:\n%+v\n%+v", a.Shared, b.Shared)
	}
	c := WithAWG3(DeriveAWGParamsForEnd("seed-b", "master", false), "seed-b")
	if c.Shared.HeaderProtectionKey == a.Shared.HeaderProtectionKey {
		t.Error("different tunnel seeds must yield different header-protection keys")
	}
}

// TestWithAWG3KeyIs32Bytes — the module's key is a chacha20 key; anything else is
// rejected by setconf on the node.
func TestWithAWG3KeyIs32Bytes(t *testing.T) {
	p := WithAWG3(DeriveAWGParamsForEnd("seed", "master", false), "seed")
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
// header protection imposes and that the kernel accepts silently when violated
//. Sweeping many seeds because the S values are themselves derived.
func TestWithAWG3AlwaysValidates(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		p := WithAWG3(DeriveAWGParamsForEnd(seed, "master", false), seed)
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
// rejected. Randomising both ranges is the whole point of the 3.0 timers, so the
// bands have to be constructed so the invariant cannot be violated by any seed.
func TestWithAWG3TimerOrdering(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := "tunnel-" + strconv.Itoa(i)
		s := WithAWG3(DeriveAWGParamsForEnd(seed, "master", false), seed).Shared
		_, rekeyHi := splitRange(t, s.RekeyAfterTime)
		rejectLo, _ := splitRange(t, s.RejectAfterTime)
		if rekeyHi >= rejectLo {
			t.Fatalf("seed %q: RekeyAfterTime %q can outlast RejectAfterTime %q — the session is rejected before rekey starts",
				seed, s.RekeyAfterTime, s.RejectAfterTime)
		}
	}
}

// TestWithAWG3TimersAreRanges — a scalar timer is a timing fingerprint, which is
// the passive-classification vector ADR-0025 names as the real adversary and the
// reason the 3.0 timers exist at all. A derivation that collapsed them to single
// values would look fine and buy nothing.
func TestWithAWG3TimersAreRanges(t *testing.T) {
	s := WithAWG3(DeriveAWGParamsForEnd("seed", "master", false), "seed").Shared
	for _, f := range []struct{ name, value string }{
		{"RekeyAfterTime", s.RekeyAfterTime},
		{"RekeyTimeout", s.RekeyTimeout},
		{"RejectAfterTime", s.RejectAfterTime},
		{"KeepaliveTimeout", s.KeepaliveTimeout},
	} {
		lo, hi := splitRange(t, f.value)
		if lo >= hi {
			t.Errorf("%s = %q is a fixed value, not a range", f.name, f.value)
		}
	}
}

// TestWithAWG3LeavesContentPaddingUnset is a deliberate, load-bearing omission.
// ContentPaddingAddition rides on EVERY data packet the way S4 does, so deriving a
// non-zero value would silently eat the MTU cushion that AWGExtraOverhead sizes
// and black-hole full-size packets. Enabling it means folding it into
// the MTU chain first.
func TestWithAWG3LeavesContentPaddingUnset(t *testing.T) {
	s := WithAWG3(DeriveAWGParamsForEnd("seed", "master", false), "seed").Shared
	if s.ContentPaddingAddition != "" {
		t.Errorf("ContentPaddingAddition must stay unset until it is part of the MTU computation, got %q", s.ContentPaddingAddition)
	}
}

// TestWithAWG3PreservesAWG2 — the 3.0 block is additive; nothing about the 2.0
// params may shift, or an in-place upgrade would rewrite every interface.
func TestWithAWG3PreservesAWG2(t *testing.T) {
	base := DeriveAWGParamsForEnd("seed", "master", false)
	got := WithAWG3(base, "seed")
	if got.Local != base.Local {
		t.Errorf("local params must be untouched:\n%+v\n%+v", got.Local, base.Local)
	}
	if got.Shared.S1 != base.Shared.S1 || got.Shared.S4 != base.Shared.S4 ||
		got.Shared.H1 != base.Shared.H1 || got.Shared.H4 != base.Shared.H4 {
		t.Error("AWG 2.0 shared params must be untouched")
	}
	if base.AWG3Enabled() {
		t.Error("the base derivation must stay pure AWG 2.0")
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
	s := WithAWG3HeaderProtection(DeriveAWGParamsForEnd(seed, "client", false), seed).Shared
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
		whole := WithAWG3(base, seed)
		composed := WithAWG3HeaderProtection(WithAWG3Timers(base, seed), seed)
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
