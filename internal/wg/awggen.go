package wg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// AmneziaWG generation defaults and bounds. The shared params (H ranges, S) are
// derived deterministically from a per-tunnel seed so BOTH ends compute the
// identical set without any coordination/storage — required, since S1-S4 and
// H1-H4 must match between server and client. The local params (Jc/Jmin/Jmax and
// the I1-I5 signature packets) MAY differ per end, so each end derives its own
// from a per-end seed (see DeriveAWGParamsForEnd).
const (
	// Header ranges are placed in four non-overlapping bands across [hBase, hTop],
	// each band carrying a sub-range of width hRangeWidth (≈ the wg-easy example).
	hBase       = 100_000_00    // 10,000,000
	hTop        = 2_000_000_000 // < 2^31, leaves headroom
	hRangeWidth = 130_000_000   // matches the wg-easy example's ~130M-wide ranges

	// S1/S2/S3 (init/response/cookie handshake junk). Range kept within the Amnezia
	// docs' recommended 0-64 (docs.amnezia.org). They have no per-packet MTU cost.
	sLow  = 15
	sHigh = 64

	// S4 (transport_packet_junk_size) is prepended to EVERY data packet, so unlike
	// S1-S3 it consumes per-packet MTU. Bounded to the Amnezia docs' 0-32 range
	// (well within AWGExtraOverhead, so a full data packet never fragments;
	// TestS4FitsMTUCushion guards s4High ≤ AWGExtraOverhead). Never 0: AWG-2.0
	// transport masking is mandatory.
	s4Low  = 16
	s4High = 32

	// AmneziaWG message-size collision avoidance. The userspace
	// amneziawg-go receiver classifies a packet by its WIRE SIZE first. A genuine
	// transport DATA packet has wire size 32+S4+16k (k≥0); the decorated handshake
	// sizes are {148+S1, 92+S2, 64+S3}. Two ways a real data packet gets dropped:
	//   A. it lands EXACTLY on a handshake size ((H-(32+S4)) a non-negative multiple
	//      of 16) → the magic is read at the wrong junk offset and the packet is
	//      discarded with no recovery (the dominant, code-traceable hazard);
	//   B. one data grid point sits within awgShadowDelta of TWO handshake sizes at
	//      once (the adjacent-pair shadow — needed for the S1/S2 ≈ adjacent case).
	// awgSizesSafe rejects both; DeriveAWGShared iterates S1-S4 until it holds. See
	// the live 11-point oracle in awggen_test.go.
	awgShadowDelta = 4   // clause B: forbidden if a grid point is within +4 of two handshake sizes
	maxSafeSIters  = 256 // S1-S4 re-derivation attempts before falling back to Amnezia defaults

	// junkS4Margin keeps Jmin a safe distance above S4 (see deriveJunk / the Jmin
	// floor in DeriveAWGParamsForEnd). A receiver strips S4 bytes from an incoming
	// junk packet before reading the 4-byte message type; amneziawg-go ≤ 20251104
	// (shipped in mihomo up to ≥ v1.19.27) does this WITHOUT a length guard, so a junk
	// packet shorter than S4+4 panics it (`slice bounds out of range [S4:len]` in
	// handleTransport). Guaranteeing every junk packet ≥ S4 + margin avoids it on the
	// buggy version (newer amneziawg-go added the guard). Verified: with Jmin<S4
	// the master↔exit tunnel crash-looped mihomo v1.19.27; flooring Jmin fixes it.
	junkS4Margin = domain.AWGJunkS4Margin

	// Junk-packet decoy bounds. Jc/Jmin/Jmax MAY differ per end (the receiver
	// drops the other end's junk by size, so the values need not match), so we
	// derive them per-end from the seed to give every interface its own junk
	// profile instead of a fleet-wide constant signature. The bounds stay inside
	// the AmneziaWG recommendations (Jc 4-12) and keep the per-handshake junk
	// overhead modest (Jmax well under the 1280 ceiling).
	jcLow, jcHigh     = 4, 10  // junk packet count (Amnezia docs cap Jc at 10)
	jminLow, jminHigh = 8, 40  // lower bound of the junk size window
	jGapLow, jGapHigh = 24, 88 // Jmax = Jmin + gap, so Jmin < Jmax always holds

	// awgSignatureSlots is the number of I-packet (I1-I5) slots the domain model
	// carries. We fill the first two (STUN, QUIC); I3-I5 stay empty (see
	// deriveSignatures and ADR-0033's amendment).
	awgSignatureSlots = 5

	// stunBindingI1 is the first cover packet: a canonical STUN Binding Request —
	// message type 0x0001, message length 0x0000, magic cookie 0x2112a442 (8 bytes),
	// then a 12-byte transaction ID. `<r 12>` regenerates the TID on every handshake,
	// so the CONTENT is fresh each time while the SHAPE stays a valid 20-byte request.
	// The shape cannot vary without ceasing to be STUN (the TID is fixed at 96 bits by
	// RFC 5389), so I1 is deliberately UNIFORM across every end; per-end uniqueness is
	// carried by the QUIC packet in I2.
	stunBindingI1 = "<b 0x000100002112a442><r 12>"
)

// DeriveAWGLocal returns the local (per-end) AmneziaWG parameters for one end:
// the derived junk-packet decoy params (Jc/Jmin/Jmax) plus generated I1-I5
// signature templates keyed by seed. Local params MAY differ between the two ends
// of a tunnel, so callers pass
// a per-end seed. kernel selects the CPS-tag set: true allows the <c>/<t> tags
// (kernel-module interfaces via awg-quick); false restricts to <b>/<r>/<rc>/<rd>
// for userspace WireGuard-Go (mihomo proxies, Amnezia clients).
func DeriveAWGLocal(seed string, kernel bool) domain.AWGLocal {
	sig := deriveSignatures(seed, kernel)
	jc, jmin, jmax := deriveJunk(seed)
	return domain.AWGLocal{
		Jc: jc, Jmin: jmin, Jmax: jmax,
		I1: sig[0], I2: sig[1], I3: sig[2], I4: sig[3], I5: sig[4],
	}
}

// deriveJunk derives this end's junk-packet decoy parameters (Jc/Jmin/Jmax) from
// seed. It is keyed off a sub-seed independent of the I1-I5 signature bytes so the
// junk profile and the signature profile vary independently. The result always
// satisfies the domain invariants (Jc in [1,128], Jmin < Jmax ≤ 1280).
func deriveJunk(seed string) (jc, jmin, jmax int) {
	d := newDetStream(seed + "|junk")
	jc = jcLow + d.intn(jcHigh-jcLow+1)
	jmin = jminLow + d.intn(jminHigh-jminLow+1)
	jmax = jmin + jGapLow + d.intn(jGapHigh-jGapLow+1)
	return jc, jmin, jmax
}

// deriveSignatures generates the I1-I5 CPS templates from seed. The I-packets go
// out in order BEFORE the WireGuard handshake (kernel send.c, amneziawg-go
// device/send.go send every filled slot, then the Jc junk, then the initiation).
// We fill exactly two: I1 a canonical STUN Binding Request, I2 a full QUIC v1
// client Initial; I3-I5 stay empty.
//
// This is an amendment to ADR-0033, decided by a field A/B across several RU
// mobile carriers and a home ISP. The prior design filled all five slots
// with opaque noise `<r N>`; that measured WORST on every mobile carrier — the
// operators' per-flow prefix filter hard-blocked the opening (the server never
// answered, rx=0) — while a valid protocol cover was admitted. A single cover is
// carrier- and time-varying (STUN led on carrier A in one window and was blocked
// in another), so the two-packet STUN+QUIC opening is a hedge: when one protocol is
// being dropped, the other carries the flow. Measured, I1 STUN + I2 QUIC got through every
// time on carriers A and B and beat STUN-alone on carrier B although both send the
// same I1 — proof the filter reads past the first packet.
//
// The stand's adversary (a stateful censor that follows the flow) wants the
// OPPOSITE: a STUN/QUIC opening in front of a WireGuard handshake on the same
// 5-tuple is a chimera it can key on. That case is served by the per-credential
// prologue knob (ADR-0033), which can select none/noise; this default targets the
// mass mobile user's dumb prefix filter.
//
// Grammar (verified against amneziawg-linux-kernel-module junk.c jp_parse_tags):
// `<b 0xHEX>` is static bytes (even hex), `<r N>` is N bytes the module regenerates
// on every handshake initiation. Both are accepted by kernel and userspace alike,
// unlike the kernel-only `<c>`/`<t>`, so the `kernel` profile does not differ.
func deriveSignatures(seed string, kernel bool) [awgSignatureSlots]string {
	_ = kernel // combo uses only <b>/<r>, valid for both profiles; <c>/<t> are kernel-only
	var out [awgSignatureSlots]string

	// I1: canonical STUN Binding Request, uniform across ends (see stunBindingI1).
	out[0] = stunBindingI1

	// I2: a full QUIC v1 client Initial (quicinitial.go) — padded to a client-typical
	// size and sealed with the real Initial keys, so it passes the size and
	// decryption checks a QUIC-aware filter runs. Every choice in it is per end.
	i2, err := quicInitialCover(seed)
	if err != nil {
		// Unreachable: the builder fails only on a ClientHello that outgrows the
		// smallest datagram, which the tests rule out for every choice.
		panic(fmt.Sprintf("wg: QUIC cover for seed %q: %v", seed, err))
	}
	out[1] = i2

	// I3-I5 stay empty: the field A/B showed two packets suffice, and more distinct
	// protocols only add signal against a stateful censor.
	return out
}

// detStream is a deterministic byte stream seeded by a string: an unbounded
// SHA-256 keystream (block = sha256(seed || counter)). Same seed ⇒ same bytes, so
// signature generation is idempotent across reconciles (no config churn).
type detStream struct {
	seed []byte
	buf  []byte
	ctr  uint32
}

func newDetStream(seed string) *detStream { return &detStream{seed: []byte(seed)} }

func (d *detStream) next() byte {
	if len(d.buf) == 0 {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], d.ctr)
		d.ctr++
		sum := sha256.Sum256(append(append([]byte(nil), d.seed...), c[:]...))
		d.buf = sum[:]
	}
	b := d.buf[0]
	d.buf = d.buf[1:]
	return b
}

// intn returns a deterministic value in [0,n) for 0 < n ≤ 256.
func (d *detStream) intn(n int) int { return int(d.next()) % n }

// TunnelSeed builds a stable, order-independent seed for the tunnel between two
// nodes, optionally salted. Both ends call it with the same names and salt and
// therefore derive the same shared AmneziaWG parameters.
func TunnelSeed(nodeA, nodeB, salt string) string {
	pair := []string{nodeA, nodeB}
	sort.Strings(pair)
	return strings.Join(pair, "|") + "|" + salt
}

// DeriveAWGShared deterministically derives a valid AWGShared from seed: four
// non-overlapping header ranges (one per band) plus S1/S2. The same seed always
// yields the same parameters.
func DeriveAWGShared(seed string) domain.AWGShared {
	sum := sha256.Sum256([]byte(seed))

	// One header range per band guarantees non-overlap. The band span must hold
	// a full hRangeWidth-wide sub-range.
	bandSpan := (hTop - hBase) / 4
	headers := make([]domain.AWGHeader, 4)
	for i := 0; i < 4; i++ {
		bandStart := uint32(hBase + i*bandSpan)
		slack := uint32(bandSpan) - hRangeWidth
		off := binary.BigEndian.Uint32(sum[i*4:i*4+4]) % (slack + 1)
		min := bandStart + off
		headers[i] = domain.AWGHeader{Min: min, Max: min + hRangeWidth}
	}

	// S1-S4 (init/response/cookie/transport junk) are AmneziaWG 2.0 shared params,
	// derived from the same tunnel seed so both ends compute identical values. They
	// are iterated until the message-size set is collision-safe for the userspace
	// amneziawg-go classifier — see deriveSafeS / awgSizesSafe.
	s1, s2, s3, s4 := deriveSafeS(seed)

	return domain.AWGShared{
		H1: headers[0], H2: headers[1], H3: headers[2], H4: headers[3],
		S1: s1, S2: s2, S3: s3, S4: s4,
	}
}

// deriveSafeS deterministically derives (S1,S2,S3,S4) from seed, re-deriving from
// an incremented sub-seed until the four decorated message sizes avoid the
// amneziawg-go classifier collisions (awgSizesSafe). Both tunnel ends
// run the identical loop and converge on the same values. The safe set is large
// (a handful of mod-16 residues are excluded), so it converges in the first few
// iterations; the Amnezia-default fallback is a proven-safe last resort.
func deriveSafeS(seed string) (s1, s2, s3, s4 int) {
	for i := 0; i < maxSafeSIters; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|S|%d", seed, i)))
		s1 = int(mapU32(uint32(h[0])<<8|uint32(h[1]), sLow, sHigh))
		s2 = int(mapU32(uint32(h[2])<<8|uint32(h[3]), sLow, sHigh))
		if s1+56 == s2 { // S1+56 != S2 (anti-detection), enforced deterministically
			if s2 < sHigh {
				s2++
			} else {
				s2--
			}
		}
		s3 = int(mapU32(uint32(h[4])<<8|uint32(h[5]), sLow, sHigh))
		s4 = int(mapU32(uint32(h[6])<<8|uint32(h[7]), s4Low, s4High))
		if awgSizesSafe(s1, s2, s3, s4) {
			return s1, s2, s3, s4
		}
	}
	// Fallback (effectively unreachable): Amnezia's commercial defaults, oracle-PASS.
	return 15, 18, 20, 23
}

// awgSizesSafe reports whether the AmneziaWG message-size set avoids the two ways a
// genuine transport DATA packet gets misclassified and dropped by the userspace
// amneziawg-go size classifier. Decorated handshake sizes are
// {148+S1, 92+S2, 64+S3}; a data packet has wire size 32+S4+16k (k≥0). It returns
// false when (A) a data size lands exactly on a handshake size — (H-(32+S4)) a
// non-negative multiple of 16 — or (B) one data grid point sits within
// awgShadowDelta of two handshake sizes at once, or the four decorated sizes are
// not all distinct (which amneziawg-go rejects outright).
func awgSizesSafe(s1, s2, s3, s4 int) bool {
	t0 := 32 + s4
	hs := [3]int{148 + s1, 92 + s2, 64 + s3}

	// All four decorated sizes must be distinct (init/resp/cookie/transport).
	sizes := [4]int{hs[0], hs[1], hs[2], t0}
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			if sizes[i] == sizes[j] {
				return false
			}
		}
	}

	// Clause A: no data grid point lands exactly on a handshake size.
	for _, h := range hs {
		if h >= t0 && (h-t0)%16 == 0 {
			return false
		}
	}

	// Clause B: no data grid point within awgShadowDelta of two handshake sizes.
	maxH := hs[0]
	for _, h := range hs[1:] {
		if h > maxH {
			maxH = h
		}
	}
	// A shadowing grid point can sit up to awgShadowDelta ABOVE the largest handshake
	// size (g-H ∈ [0,δ] ⇒ g ≤ maxH+δ), so scan a little past maxH.
	for g := t0; g <= maxH+awgShadowDelta; g += 16 {
		near := 0
		for _, h := range hs {
			if d := g - h; d >= 0 && d <= awgShadowDelta {
				near++
			}
		}
		if near >= 2 {
			return false
		}
	}
	return true
}

// DeriveAWGParamsForEnd returns one tunnel END's full AmneziaWG config: shared
// params derived from the tunnel seed (byte-for-byte identical on both ends) plus
// this end's local params (derived junk decoy + generated I1-I5 signatures) keyed
// by a per-end seed, so the two ends differ as the spec allows. kernel=true enables the
// <c>/<t> CPS tags for kernel-module interfaces (awg-quick); false keeps the
// signatures userspace-safe (mihomo proxies, Amnezia clients).
func DeriveAWGParamsForEnd(tunnelSeed, endLabel string, kernel bool) domain.AWGParams {
	shared := DeriveAWGShared(tunnelSeed)
	local := DeriveAWGLocal(tunnelSeed+"|end|"+endLabel, kernel)
	// Floor Jmin above S4 so no junk packet this end SENDS is short enough to
	// underflow a peer that strips S4 from incoming junk before length-checking it
	// (amneziawg-go ≤20251104 bug; see junkS4Margin). S4 is shared, so flooring on
	// the sending end protects the receiving end.
	//
	// The shift is CONSTANT for a given S4 — every draw moves by the same amount —
	// rather than per-end "raise it to the floor if it is under". That version was a
	// clamp wearing a shift's clothes: Jmin is drawn from [8,40] and the floor lands
	// in [24,40], so it pushed 77% of ends onto exactly S4+junkS4Margin and left 17
	// distinct values across 2000 tunnels. Jmin stopped being a decoy and became a
	// function of S4 — and S4 is SHARED, printed in every client config, so one
	// captured config would have given away the junk window of every tunnel with the
	// same S4. Moving the whole band keeps distinct draws distinct. Jmax rides along
	// to preserve the Jmin<Jmax gap; the worst case (40+88 shifted by 32) is 160,
	// well under the 1280 ceiling. Same correction floorClientJunk already applies
	// to the client decoy.
	if shift := shared.S4 + junkS4Margin - jminLow; shift > 0 {
		local.Jmin += shift
		local.Jmax += shift
	}
	return domain.AWGParams{Shared: shared, Local: local}
}

// DeriveAWGParams is the back-compat single-seed form keyed by the tunnel seed
// alone, with userspace-safe signatures. Prefer DeriveAWGParamsForEnd so each end
// gets its own I1-I5 and kernel ends can use the richer CPS tags.
func DeriveAWGParams(seed string) domain.AWGParams {
	return DeriveAWGParamsForEnd(seed, "", false)
}

// mapU32 maps v into the inclusive range [lo, hi].
func mapU32(v uint32, lo, hi uint32) uint32 {
	span := hi - lo + 1
	return lo + v%span
}
