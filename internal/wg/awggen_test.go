package wg

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func TestDeriveAWGParamsValid(t *testing.T) {
	for _, seed := range []string{"a|b|", "exit-de-1|master-xa-1|salt", "x", ""} {
		p := DeriveAWGParams(seed)
		if err := p.Validate(); err != nil {
			t.Errorf("seed %q produced invalid AWG params: %v", seed, err)
		}
	}
}

// TestDeriveAWGAllJunkSizesGenerated verifies the FULL S1-S4 set is derived
// (none left at zero) across many seeds — S3/S4 (AmneziaWG 2.0) were once left 0,
// producing "stub" configs. All four are shared, so both ends must agree.
func TestDeriveAWGAllJunkSizesGenerated(t *testing.T) {
	for i := 0; i < 1000; i++ {
		s := DeriveAWGShared(string(rune(i)) + "|tunnel|salt")
		if s.S1 == 0 || s.S2 == 0 || s.S3 == 0 || s.S4 == 0 {
			t.Fatalf("seed %d: a junk size is zero (S1=%d S2=%d S3=%d S4=%d) — all must be generated",
				i, s.S1, s.S2, s.S3, s.S4)
		}
	}
}

// TestS4FitsMTUCushion guards the S4↔MTU coupling: S4 junk is added to every data
// packet, so the derived value must stay within the AmneziaWG MTU cushion or
// full-size data packets fragment at the physical link.
func TestS4FitsMTUCushion(t *testing.T) {
	if s4High > AWGExtraOverhead {
		t.Fatalf("s4High (%d) must be <= AWGExtraOverhead (%d) or data packets fragment", s4High, AWGExtraOverhead)
	}
	for i := 0; i < 1000; i++ {
		s := DeriveAWGShared(string(rune(i)) + "|s4|salt")
		if s.S4 < s4Low || s.S4 > s4High {
			t.Fatalf("seed %d: S4=%d outside [%d,%d]", i, s.S4, s4Low, s4High)
		}
	}
}

// TestJminAboveS4 guards the amneziawg-go ≤20251104 crash: a junk packet shorter
// than S4 underflows the receiver's S4-strip. Every derived end must have
// Jmin ≥ S4 (+margin), so no junk packet this end sends can crash a buggy peer.
func TestJminAboveS4(t *testing.T) {
	for i := 0; i < 2000; i++ {
		for _, end := range []string{"exit", "master", ""} {
			p := DeriveAWGParamsForEnd(string(rune(i))+"|tun|salt", end, i%2 == 0)
			if p.Local.Jmin < p.Shared.S4+junkS4Margin {
				t.Fatalf("seed %d end %q: Jmin=%d < S4+margin=%d+%d", i, end, p.Local.Jmin, p.Shared.S4, junkS4Margin)
			}
			if p.Local.Jmin >= p.Local.Jmax || p.Local.Jmax > awgJMaxLimitTest {
				t.Fatalf("seed %d end %q: bad Jmin/Jmax after floor: %d/%d", i, end, p.Local.Jmin, p.Local.Jmax)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("seed %d end %q: invalid after Jmin floor: %v", i, end, err)
			}
		}
	}
}

const awgJMaxLimitTest = 1280

// TestAWGSizesSafeOracle pins awgSizesSafe against the 11-point LIVE oracle that
// diagnosed an earlier finding: nine (S1,S2,S3,S4) sets that work on the fleet and two that
// break it (~50% of new TLS connections dropped). The predicate must classify every
// row correctly — a real data packet of wire size 32+S4+16k must never alias a
// handshake size (clause A) nor shadow an adjacent handshake pair (clause B).
func TestAWGSizesSafeOracle(t *testing.T) {
	for _, c := range []struct {
		s1, s2, s3, s4 int
		safe           bool
		note           string
	}{
		{19, 145, 76, 0, true, "exit-2 S4=0"},
		{19, 145, 76, 100, true, "exit-2 S4=100"},
		{71, 126, 68, 0, true, "exit-1 S4=0"},
		{71, 126, 68, 23, true, "exit-1 S4=23 (only S4 changed from the fail row)"},
		{15, 18, 20, 23, true, "Amnezia client defaults"},
		{83, 29, 91, 112, true, "prod exit-a"},
		{47, 50, 2, 9, true, "prod exit-2"},
		{102, 67, 143, 38, true, "prod exit-b"},
		{19, 94, 72, 126, true, "prod exit-c"},
		{19, 145, 76, 39, false, "exit-2 S4=39 — data size 167 aliases init (clause A)"},
		{71, 126, 68, 62, false, "exit-1 S4=62 — grid 222 shadows init=219 & resp=218 (clause B)"},
	} {
		if got := awgSizesSafe(c.s1, c.s2, c.s3, c.s4); got != c.safe {
			t.Errorf("awgSizesSafe(%d,%d,%d,%d)=%v want %v — %s", c.s1, c.s2, c.s3, c.s4, got, c.safe, c.note)
		}
	}
}

// TestDeriveSharedAlwaysSizeSafe guards an earlier finding end to end: every derived tunnel
// must carry a NON-ZERO S4 (AWG-2.0 transport masking is mandatory) AND a
// collision-safe message-size set, across many seeds and both tunnel ends.
func TestDeriveSharedAlwaysSizeSafe(t *testing.T) {
	for i := 0; i < 3000; i++ {
		s := DeriveAWGShared(string(rune(i)) + "|tunnel|salt")
		if s.S4 == 0 {
			t.Fatalf("seed %d: S4=0 — AWG-2.0 transport junk must be present", i)
		}
		if !awgSizesSafe(s.S1, s.S2, s.S3, s.S4) {
			t.Fatalf("seed %d: derived size-UNSAFE S1=%d S2=%d S3=%d S4=%d", i, s.S1, s.S2, s.S3, s.S4)
		}
	}
}

func TestDeriveAWGDeterministic(t *testing.T) {
	seed := "exit-de-1|master-xa-1|salt"
	a := DeriveAWGShared(seed)
	b := DeriveAWGShared(seed)
	if a != b {
		t.Fatalf("same seed must yield identical shared params:\n%+v\n%+v", a, b)
	}
}

func TestDeriveAWGDiffersBySeed(t *testing.T) {
	if DeriveAWGShared("tunnel-1") == DeriveAWGShared("tunnel-2") {
		t.Fatal("different seeds should yield different params")
	}
}

func TestTunnelSeedOrderIndependent(t *testing.T) {
	if TunnelSeed("master-xa-1", "exit-de-1", "s") != TunnelSeed("exit-de-1", "master-xa-1", "s") {
		t.Fatal("TunnelSeed must be order-independent")
	}
	if DeriveAWGShared(TunnelSeed("a", "b", "salt")) != DeriveAWGShared(TunnelSeed("b", "a", "salt")) {
		t.Fatal("both tunnel ends must derive identical shared AWG params")
	}
}

func TestDeriveAWGHeaderRangesNonOverlapping(t *testing.T) {
	// Exercise many seeds; the generated header ranges must always be valid and
	// non-overlapping (the band partition guarantees it).
	for i := 0; i < 1000; i++ {
		p := DeriveAWGParams(string(rune(i)) + "-seed")
		if err := p.Validate(); err != nil {
			t.Fatalf("seed %d invalid: %v", i, err)
		}
	}
}

// TestDeriveSignaturesAlwaysGenerated verifies every end gets all five I-packets
// and they are valid CPS templates, across many seeds and both tag profiles.
func TestDeriveSignaturesAlwaysGenerated(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := string(rune(i)) + "-tunnel"
		for _, kernel := range []bool{true, false} {
			loc := DeriveAWGLocal(seed, kernel)
			sigs := []string{loc.I1, loc.I2, loc.I3, loc.I4, loc.I5}
			for k, s := range sigs {
				if s == "" {
					t.Fatalf("seed %q kernel=%v: I%d is empty", seed, kernel, k+1)
				}
				if !strings.HasPrefix(s, "<b 0x") {
					t.Fatalf("seed %q I%d missing literal prefix: %q", seed, k+1, s)
				}
			}
		}
	}
}

// TestICoverProtocolMimicry verifies the I-packets imitate a REAL UDP protocol
// (QUIC / STUN / DTLS) rather than random noise: every slot of a tunnel carries the
// SAME cover protocol's wire signature, the choice VARIES across tunnels, and the
// templates are userspace-safe (no <c>/<t>, which would corrupt the protocol layout)
// so both the kernel and userspace profiles validate identically.
func TestICoverProtocolMimicry(t *testing.T) {
	classify := func(i1 string) string {
		switch {
		case strings.HasPrefix(i1, "<b 0x16fefd"): // DTLS 1.2 handshake record
			return "dtls"
		case strings.HasPrefix(i1, "<b 0x0001"): // STUN Binding Request (type 0x0001)
			return "stun"
		case strings.HasPrefix(i1, "<b 0xc") && strings.Contains(i1, "00000001"): // QUIC v1 Initial
			return "quic"
		default:
			return ""
		}
	}

	protos := map[string]bool{}
	fleetI1 := map[string]bool{}
	for i := 0; i < 300; i++ {
		seed := string(rune(i)) + "-tunnel"
		for _, kernel := range []bool{true, false} {
			loc := DeriveAWGLocal(seed, kernel)
			kp := domain.AWGParams{Shared: DeriveAWGShared(seed), Local: loc}
			// Both profiles must be userspace-safe (mimicry uses no <c>/<t>).
			if err := kp.ValidateUserspace(); err != nil {
				t.Fatalf("seed %q kernel=%v: mimicry must validate userspace: %v", seed, kernel, err)
			}
			proto := classify(loc.I1)
			if proto == "" {
				t.Fatalf("seed %q I1 matches no cover protocol: %q", seed, loc.I1)
			}
			slots := []string{loc.I1, loc.I2, loc.I3, loc.I4, loc.I5}
			distinct := map[string]bool{}
			for k, s := range slots {
				if strings.Contains(s, "<c>") || strings.Contains(s, "<t>") {
					t.Fatalf("seed %q I%d uses <c>/<t> (breaks protocol mimicry): %q", seed, k+1, s)
				}
				if classify(s) != proto { // every slot is the SAME protocol (a flow is one protocol)
					t.Fatalf("seed %q I%d is a different protocol than I1 (%s): %q", seed, k+1, proto, s)
				}
				distinct[s] = true
			}
			// The five slots must NOT all be one static byte string (the bug fixed
			// here: a fixed STUN template made every slot — and both ends — identical).
			if len(distinct) < 2 {
				t.Errorf("seed %q kernel=%v: I1-I5 are all identical (%q) — per-slot field variation broken", seed, kernel, loc.I1)
			}
			protos[proto] = true
			fleetI1[loc.I1] = true
		}
	}
	// Over 300 seeds we must see real variation across the cover protocols AND across
	// I1 templates (no fleet-wide static fingerprint).
	if len(protos) < 2 {
		t.Errorf("cover protocol barely varies across seeds: saw %v", protos)
	}
	// I1 must be highly varied across the 300 distinct tunnel seeds (no static
	// fleet-wide fingerprint). Some collision is fine — the templates still look like
	// genuine QUIC/STUN/DTLS — but the bulk must differ.
	if len(fleetI1) < 250 {
		t.Errorf("I1 templates barely vary across the fleet: only %d distinct of 300 seeds", len(fleetI1))
	}
}

// TestDeriveEndsDifferButShareShared checks the two ends of one tunnel agree on
// shared params yet carry their own signatures, and that generation is stable.
func TestDeriveEndsDifferButShareShared(t *testing.T) {
	seed := TunnelSeed("exit-de-1", "master-xa-1", awgTestSalt)
	exit := DeriveAWGParamsForEnd(seed, "exit", true)
	master := DeriveAWGParamsForEnd(seed, "master", false)

	if exit.Shared != master.Shared {
		t.Fatal("both ends must share identical S/H params")
	}
	exitI := exit.Local.I1 + exit.Local.I2 + exit.Local.I3 + exit.Local.I4 + exit.Local.I5
	masterI := master.Local.I1 + master.Local.I2 + master.Local.I3 + master.Local.I4 + master.Local.I5
	if exitI == masterI {
		t.Fatal("the two ends should derive distinct I-packet signatures")
	}
	// Idempotent: same inputs ⇒ same output (no reconcile churn).
	if again := DeriveAWGParamsForEnd(seed, "exit", true); again.Local != exit.Local {
		t.Fatal("DeriveAWGParamsForEnd must be deterministic")
	}
}

// TestDeriveJunkPerEnd verifies the junk decoy params (Jc/Jmin/Jmax) are derived
// per-end (not a fleet-wide constant), stay within the domain invariants, and are
// deterministic. The two ends of a tunnel may carry different junk profiles.
func TestDeriveJunkPerEnd(t *testing.T) {
	seed := TunnelSeed("exit-de-1", "master-xa-1", awgTestSalt)
	exit := DeriveAWGParamsForEnd(seed, "exit", true)
	master := DeriveAWGParamsForEnd(seed, "master", false)

	for _, tc := range []struct {
		end string
		l   domain.AWGLocal
	}{{"exit", exit.Local}, {"master", master.Local}} {
		if tc.l.Jc < 1 || tc.l.Jc > 128 {
			t.Errorf("%s: Jc %d outside [1,128]", tc.end, tc.l.Jc)
		}
		if !(tc.l.Jmin < tc.l.Jmax) || tc.l.Jmax > 1280 {
			t.Errorf("%s: junk window %d-%d violates Jmin<Jmax≤1280", tc.end, tc.l.Jmin, tc.l.Jmax)
		}
	}

	// Two ends should not share an identical junk profile in lockstep with the
	// shared params — exercise that the per-end seed actually moves the values.
	if exit.Local.Jc == master.Local.Jc &&
		exit.Local.Jmin == master.Local.Jmin &&
		exit.Local.Jmax == master.Local.Jmax {
		t.Error("both ends derived an identical junk profile; per-end derivation is not varying")
	}

	// Deterministic: same inputs ⇒ same junk.
	if again := DeriveAWGParamsForEnd(seed, "exit", true); again.Local.Jc != exit.Local.Jc ||
		again.Local.Jmin != exit.Local.Jmin || again.Local.Jmax != exit.Local.Jmax {
		t.Error("junk derivation must be deterministic")
	}
}

// TestDeriveJunkNotFleetConstant confirms the junk profile actually varies across
// tunnels (it is no longer a hardcoded 8/8/80 for every interface in the fleet).
func TestDeriveJunkNotFleetConstant(t *testing.T) {
	seen := make(map[[3]int]bool)
	for i := 0; i < 200; i++ {
		l := DeriveAWGLocal(string(rune(i))+"-tunnel|end|exit", false)
		seen[[3]int{l.Jc, l.Jmin, l.Jmax}] = true
	}
	if len(seen) < 10 {
		t.Errorf("junk profile barely varies across 200 seeds (%d distinct); decoy is too static", len(seen))
	}
}

// FuzzDeriveAWGParamsForEnd hardens the generator: for ANY seed/label, derived
// params must satisfy the kernel and (for the userspace profile) userspace
// validation. This goes beyond the rune-indexed loops above.
func FuzzDeriveAWGParamsForEnd(f *testing.F) {
	f.Add("exit-de-1|master-xa-1|salt", "exit")
	f.Add("", "")
	f.Add("x", "master")
	f.Fuzz(func(t *testing.T, seed, label string) {
		kp := DeriveAWGParamsForEnd(seed, label, true)
		if err := kp.Validate(); err != nil {
			t.Fatalf("kernel params invalid for seed=%q label=%q: %v", seed, label, err)
		}
		up := DeriveAWGParamsForEnd(seed, label, false)
		if err := up.ValidateUserspace(); err != nil {
			t.Fatalf("userspace params invalid for seed=%q label=%q: %v", seed, label, err)
		}
		// Both ends must always agree on shared params for the same tunnel seed.
		if other := DeriveAWGParamsForEnd(seed, label+"-other", true); other.Shared != kp.Shared {
			t.Fatalf("shared params diverged for the same tunnel seed %q", seed)
		}
	})
}

const awgTestSalt = "wgfleet-awg-v1"
