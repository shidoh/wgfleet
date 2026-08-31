package wg

import (
	"fmt"
	"regexp"
	"strconv"
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
			}
			// What actually has to hold is that the module accepts these: an
			// unknown or malformed CPS tag is -EINVAL, not an ignored field, so a
			// bad template takes the interface down rather than degrading.
			p := DeriveAWGParamsForEnd(seed, "end", kernel)
			if err := p.Validate(); err != nil {
				t.Fatalf("seed %q kernel=%v: params invalid: %v", seed, kernel, err)
			}
			if !kernel {
				// A userspace peer additionally rejects the kernel-only tags.
				if err := p.ValidateUserspace(); err != nil {
					t.Fatalf("seed %q: userspace params invalid: %v", seed, err)
				}
			}
		}
	}
}

// TestISlotsAreOpaqueNoise pins the decision taken in ADR-0022 after the
// 2026-08-28 measurement: I1-I5 carry NO protocol structure at all.
//
// The previous design filled the slots with QUIC/STUN/DTLS templates. Measured,
// that was worse than sending nothing of the sort: the packets were recognised as
// their protocol AND malformed (the QUIC varint Length was never emitted, the DTLS
// handshake header was 4 bytes where RFC 6347 wants 12, and the length fields were
// literally `<r N>` random bytes), so a dissector got a cleaner signal out of them
// than out of noise. The same sizes filled with random bytes measured as plain UDP
// with no attribution at all. Structure is the liability here, so there must be
// none: no literal `<b ...>` bytes, one random run per slot, nothing else.
func TestISlotsAreOpaqueNoise(t *testing.T) {
	rTag := regexp.MustCompile(`^<r (\d+)>$`)

	fleetI1 := map[string]bool{}
	for i := 0; i < 300; i++ {
		seed := fmt.Sprintf("tunnel-%d", i)
		for _, kernel := range []bool{true, false} {
			loc := DeriveAWGLocal(seed, kernel)
			slots := []string{loc.I1, loc.I2, loc.I3, loc.I4, loc.I5}
			distinct := map[string]bool{}
			for k, sig := range slots {
				m := rTag.FindStringSubmatch(sig)
				if m == nil {
					t.Fatalf("seed %q I%d is not a single random run: %q", seed, k+1, sig)
				}
				// Any literal byte is a fingerprint an analyser can key on — that is
				// exactly what the measurement caught.
				if strings.Contains(sig, "<b ") {
					t.Fatalf("seed %q I%d carries literal protocol bytes: %q", seed, k+1, sig)
				}
				// <c>/<t> are kernel-only tags; a userspace peer rejects them outright.
				if strings.Contains(sig, "<c>") || strings.Contains(sig, "<t>") {
					t.Fatalf("seed %q I%d uses a kernel-only tag: %q", seed, k+1, sig)
				}
				n, err := strconv.Atoi(m[1])
				if err != nil {
					t.Fatalf("seed %q I%d has an unparsable length: %q", seed, k+1, sig)
				}
				if n < iNoiseLow || n > iNoiseHigh {
					t.Errorf("seed %q I%d length %d outside [%d,%d]", seed, k+1, n, iNoiseLow, iNoiseHigh)
				}
				distinct[sig] = true
			}
			// The five slots must not collapse to one size — that would hand back a
			// static per-interface shape.
			if len(distinct) < 2 {
				t.Errorf("seed %q kernel=%v: I1-I5 are all identical (%q)", seed, kernel, loc.I1)
			}
		}
		fleetI1[DeriveAWGLocal(seed, true).I1] = true
	}
	// Sizes are drawn from a bounded range, so exact collisions across 300 seeds are
	// expected and fine; what must not happen is the range collapsing to a handful.
	if len(fleetI1) < 40 {
		t.Errorf("I1 sizes barely vary across the fleet: only %d distinct of 300 seeds", len(fleetI1))
	}
}

// The two ends of one tunnel must not end up with the same I-packet shapes: a
// matched pair on both directions is a correlatable signature.
func TestISlotsDifferBetweenTheTwoEnds(t *testing.T) {
	same := 0
	for i := 0; i < 200; i++ {
		seed := fmt.Sprintf("tunnel-%d", i)
		a := DeriveAWGLocal(seed+"|a", true)
		b := DeriveAWGLocal(seed+"|b", true)
		if a.I1 == b.I1 && a.I2 == b.I2 && a.I3 == b.I3 && a.I4 == b.I4 && a.I5 == b.I5 {
			same++
		}
	}
	if same > 4 {
		t.Errorf("the two ends carried identical I1-I5 in %d/200 tunnels", same)
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

// Flooring Jmin must not destroy the spread it is flooring.
//
// The floor shifted each end UP TO the floor when it fell below it, so every value
// drawn under S4+margin — most of the band, since Jmin is drawn from [8,40] and the
// floor lands in [24,40] — collapsed onto exactly S4+8. Jmin then carried almost no
// entropy and was readable straight off S4, which is a SHARED parameter printed in
// every client config. A censor holding one config learns the junk window of every
// tunnel that shares that S4.
//
// A constant shift moves the whole band by one amount instead, so distinct draws
// stay distinct. This is the same correction the client decoy already carries
// (floorClientJunk); the tunnel path was left behind.
func TestDeriveAWGParamsForEndKeepsJunkSpreadAboveTheFloor(t *testing.T) {
	seen := make(map[int]int)
	atFloor, total := 0, 0
	for i := 0; i < 2000; i++ {
		p := DeriveAWGParamsForEnd(fmt.Sprintf("node-%d|node-%d|salt", i, i*7+1), "exit", true)
		floor := p.Shared.S4 + junkS4Margin
		if p.Local.Jmin < floor {
			t.Fatalf("Jmin %d is below the floor %d (S4=%d)", p.Local.Jmin, floor, p.Shared.S4)
		}
		if p.Local.Jmin >= p.Local.Jmax {
			t.Fatalf("Jmin %d >= Jmax %d", p.Local.Jmin, p.Local.Jmax)
		}
		if p.Local.Jmax > 1280 {
			t.Fatalf("Jmax %d exceeds the 1280 ceiling", p.Local.Jmax)
		}
		if p.Local.Jmin == floor {
			atFloor++
		}
		seen[p.Local.Jmin]++
		total++
	}
	// With a shift the floor is one outcome among many; with a clamp it was the
	// single most likely value by a wide margin.
	if share := float64(atFloor) / float64(total); share > 0.10 {
		t.Errorf("%.0f%% of ends sit exactly on the floor — Jmin is derivable from the shared S4", share*100)
	}
	if len(seen) < 20 {
		t.Errorf("only %d distinct Jmin values across %d tunnels; the junk window carries no entropy", len(seen), total)
	}
}
