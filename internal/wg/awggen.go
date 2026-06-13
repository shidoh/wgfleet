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

	sLow  = 15 // S1/S2 recommended range
	sHigh = 150

	// Junk-packet decoy bounds. Jc/Jmin/Jmax MAY differ per end (the receiver
	// drops the other end's junk by size, so the values need not match), so we
	// derive them per-end from the seed to give every interface its own junk
	// profile instead of a fleet-wide constant signature. The bounds stay inside
	// the AmneziaWG recommendations (Jc 4-12) and keep the per-handshake junk
	// overhead modest (Jmax well under the 1280 ceiling).
	jcLow, jcHigh     = 4, 12  // junk packet count
	jminLow, jminHigh = 8, 40  // lower bound of the junk size window
	jGapLow, jGapHigh = 24, 88 // Jmax = Jmin + gap, so Jmin < Jmax always holds

	// awgSignatureSlots is the number of I-packet slots (I1-I5) we fill.
	awgSignatureSlots = 5
	// Bounds for generated CPS templates (kept well under MESSAGE_MAX_SIZE and the
	// tools' MAX_AWG_STRING_LEN so the kernel/userspace parsers always accept them).
	bPrefixMinBytes  = 2 // literal "magic" prefix length, in bytes
	bPrefixSpanBytes = 4 // prefix is bPrefixMin .. bPrefixMin+span-1 bytes
	padMinBytes      = 4 // random-pad tag length lower bound
	padSpanBytes     = 45
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

// deriveSignatures generates the I1-I5 CPS templates from seed. Each slot is keyed
// independently so the five packets differ from one another.
func deriveSignatures(seed string, kernel bool) [awgSignatureSlots]string {
	var out [awgSignatureSlots]string
	for k := 0; k < awgSignatureSlots; k++ {
		out[k] = cpsTemplate(fmt.Sprintf("%s|I%d", seed, k+1), kernel)
	}
	return out
}

// cpsTemplate builds one deterministic AmneziaWG CPS (Custom Packet Signature)
// template. I-packets are emitted before the handshake to disguise the first
// datagrams as some other protocol — this is where the obfuscation actually
// lives. The grammar is verified against the upstream kernel parser
// (amneziawg-linux-kernel-module junk.c, jp_parse_tags):
//
//	<b 0xHEX>  literal bytes (even-length hex, prefixed 0x) — a stable per-end
//	           "magic" header that mimics a fixed protocol signature
//	<r N>      N random bytes     <rc N> N random ASCII letters   <rd N> N digits
//	<c>        4-byte packet counter      <t> 4-byte unix time
//
// <c>/<t> are KERNEL-ONLY: userspace WireGuard-Go cannot parse them, so userspace
// ends restrict to <b>/<r>/<rc>/<rd>. A receiver drops junk regardless of its
// content, so a kernel end may use <c>/<t> even when its peer is userspace.
//
// The literal prefix is deterministic (a fixed per-end signature); the random
// tags carry only a length, so the kernel fills fresh bytes on every handshake —
// stable structure, varying content.
func cpsTemplate(seed string, kernel bool) string {
	d := newDetStream(seed)
	var b strings.Builder

	// 1. Leading literal "magic" prefix.
	blen := bPrefixMinBytes + d.intn(bPrefixSpanBytes)
	b.WriteString("<b 0x")
	for i := 0; i < blen; i++ {
		fmt.Fprintf(&b, "%02x", d.next())
	}
	b.WriteString(">")

	// 2. A randomized padding tag (content reshuffled every handshake).
	b.WriteString(randPadTag(d))

	// 3. Optional evolving field (kernel only): a counter or timestamp makes the
	//    junk look like a live protocol rather than static noise.
	if kernel && d.intn(2) == 0 {
		if d.intn(2) == 0 {
			b.WriteString("<c>")
		} else {
			b.WriteString("<t>")
		}
	}

	// 4. Optional trailing pad.
	if d.intn(2) == 0 {
		b.WriteString(randPadTag(d))
	}
	return b.String()
}

// randPadTag returns a random-content padding tag (<r>/<rc>/<rd>) with a
// deterministic length; the kernel fills the bytes fresh per handshake.
func randPadTag(d *detStream) string {
	n := padMinBytes + d.intn(padSpanBytes)
	switch d.intn(3) {
	case 0:
		return fmt.Sprintf("<r %d>", n)
	case 1:
		return fmt.Sprintf("<rc %d>", n)
	default:
		return fmt.Sprintf("<rd %d>", n)
	}
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

	s1 := int(mapU32(uint32(sum[16])<<8|uint32(sum[17]), sLow, sHigh))
	s2 := int(mapU32(uint32(sum[18])<<8|uint32(sum[19]), sLow, sHigh))
	if s1+56 == s2 { // enforce S1+56 != S2 deterministically
		if s2 < sHigh {
			s2++
		} else {
			s2--
		}
	}

	return domain.AWGShared{
		H1: headers[0], H2: headers[1], H3: headers[2], H4: headers[3],
		S1: s1, S2: s2, // S3/S4 default to 0 (valid)
	}
}

// DeriveAWGParamsForEnd returns one tunnel END's full AmneziaWG config: shared
// params derived from the tunnel seed (byte-for-byte identical on both ends) plus
// this end's local params (derived junk decoy + generated I1-I5 signatures) keyed
// by a per-end seed, so the two ends differ as the spec allows. kernel=true enables the
// <c>/<t> CPS tags for kernel-module interfaces (awg-quick); false keeps the
// signatures userspace-safe (mihomo proxies, Amnezia clients).
func DeriveAWGParamsForEnd(tunnelSeed, endLabel string, kernel bool) domain.AWGParams {
	return domain.AWGParams{
		Shared: DeriveAWGShared(tunnelSeed),
		Local:  DeriveAWGLocal(tunnelSeed+"|end|"+endLabel, kernel),
	}
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
