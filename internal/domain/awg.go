package domain

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// AmneziaWG parameter limits. Verified against the upstream source
// (amneziawg-linux-kernel-module: magic_header.c, device.c
// wg_device_handle_post_config; amneziawg-tools: config.c) and the wg-easy
// compatibility table.
//
// Match/differ semantics (CRITICAL — proven by the kernel datapath):
//   - MUST be identical on both ends: S1-S4 and H1-H4. The receiver uses ITS OWN
//     junk_size (S) to strip prepended junk and ITS OWN header ranges (H) to
//     validate incoming packets (receive.c), so the sender must match.
//   - MAY differ per end: Jc, Jmin, Jmax and I1-I5. Each end sends its own junk
//     and I-packets; the peer ignores them (send.c). This matches the original
//     the wg-easy table.
const (
	awgJcMin     = 1 // junk packet count: 1 ≤ Jc ≤ 128 (recommended 4-12)
	awgJcMax     = 128
	awgJMaxLimit = 1280 // Jmin < Jmax ≤ 1280 (kernel: Jmax < MESSAGE_MAX_SIZE)

	// AWGJunkS4Margin is how far Jmin must clear S4.
	//
	// A receiver strips S4 bytes from an incoming junk packet before reading the
	// 4-byte message type. amneziawg-go ≤ 20251104 — which every Amnezia CLIENT
	// APP is built on — does that WITHOUT a length guard, so a junk packet shorter
	// than S4+4 panics it in handleTransport. Since S4 is shared and Jmin is local,
	// the constraint binds the SENDING end for the RECEIVER's benefit, which is
	// exactly the kind of cross-cutting rule that gets lost when one code path
	// derives its own local params. It lives in the validator so it cannot.
	AWGJunkS4Margin = 8
	// S1-S4 PRACTICAL caps (assuming a 1280 MTU), mirroring the README's S1/S2
	// reasoning (1280 minus the message size). The KERNEL only rejects when
	// Sn + MESSAGE_*_SIZE > MESSAGE_MAX_SIZE (65535), i.e. ~65383+, so these caps are
	// far stricter than the protocol minimum — deliberately, to avoid bloated junk.
	// S4 additionally rides on EVERY data packet, so its fleet MTU-safe bound is
	// enforced separately in the wg derivation (see wg.AWGExtraOverhead); this is
	// only the protocol-sanity cap.
	awgS1Limit = 1132 // S1: 1280 − 148 (MESSAGE_INITIATION)
	awgS2Limit = 1188 // S2: 1280 − 92 (MESSAGE_RESPONSE)
	awgS3Limit = 1216 // S3 (cookie-reply junk, AmneziaWG 1.5)
	awgS4Limit = 1248 // S4 (transport junk, AmneziaWG 1.5)

	// awgStringMaxLen mirrors the tools' MAX_AWG_STRING_LEN (5*1024) — the hard
	// cap config.c enforces on H and I string values.
	awgStringMaxLen = 5 * 1024
)

// hexBlob matches an AmneziaWG I-value hex literal: optional 0x prefix then an
// EVEN number of hex digits. The kernel's parse_b_tag rejects odd-length hex
// (len % 2 != 0), so we reject it here too rather than letting it pass Validate
// and fail at the kernel. An empty value is allowed (no I-packet in that slot).
var hexBlob = regexp.MustCompile(`^(0x)?([0-9a-fA-F]{2})*$`)

// AWGHeader is an AmneziaWG packet-header type range. AmneziaWG (1.5+) specifies
// H1-H4 as ranges "Min-Max"; the four ranges must not overlap each other so the
// header types stay distinguishable. A single value is expressed as Min==Max.
type AWGHeader struct {
	Min, Max uint32
}

func (h AWGHeader) valid() bool { return h.Min <= h.Max }

func (h AWGHeader) overlaps(o AWGHeader) bool {
	return h.Min <= o.Max && o.Min <= h.Max
}

// String renders the header as "min-max", or "min" when it is a single value.
func (h AWGHeader) String() string {
	if h.Min == h.Max {
		return fmt.Sprintf("%d", h.Min)
	}
	return fmt.Sprintf("%d-%d", h.Min, h.Max)
}

// AWGShared holds the AmneziaWG parameters that MUST be byte-for-byte identical
// between a tunnel's server and every client. A mismatch silently breaks the
// tunnel.
//
//   - H1-H4: dynamic data-packet header-type ranges; the four ranges must not
//     overlap each other.
//   - S1-S4: junk prefix sizes for init/response/cookie/data packets. S1 ≤ 1132,
//     S2 ≤ 1188, and critically S1+56 ≠ S2 (else the obfuscation is detectable).
type AWGShared struct {
	H1, H2, H3, H4 AWGHeader
	S1, S2, S3, S4 int

	// --- AmneziaWG 3.0 (see awg3.go). Empty across the board = a pure AWG 2.0
	// interface, which is what every node renders until an operator opts in. ---

	// HeaderProtectionKey is the base64 chacha20 key for header protection.
	// Setting it imposes S1-S4 >= 12; see validateAWG3.
	HeaderProtectionKey string
	// RandomTrailers appends random bytes to handshake and short data packets so
	// their sizes stop falling on fixed residues. Must match on both ends. Only
	// with header protection: the pair is what upstream's 3.1 recommends, and the
	// classifier bug it trips without equal S is worse than the residue it hides.
	RandomTrailers bool
	// ContentPaddingAddition pads transport packets. The receiver strips exactly
	// this much, so it must match on both ends.
	ContentPaddingAddition string
	// The 3.0 tunable timers, each a u16 range ("N" or "min-max") the device
	// redraws on every timer arm — the anti-fingerprint knob of ADR-0025.
	RekeyAfterTime       string
	RekeyTimeout         string
	RejectAfterTime      string
	KeepaliveTimeout     string
	MaxHandshakeAttempts string
}

// AWGLocal holds the AmneziaWG parameters that MAY differ between the two ends
// of a tunnel — each end emits its own; the peer ignores them.
//
//   - Jc: number of junk packets sent after I1-I5 (1 ≤ Jc ≤ 128, recommended 4-12).
//   - Jmin/Jmax: junk packet size bounds (Jmin < Jmax ≤ 1280).
//   - I1-I5: signature packets imitating other protocols before the handshake;
//     hex blobs or CPS tag templates. The kernel module's jp_parse_tags knows
//     exactly six tags — <b 0xHEX>, <c>, <t>, <r N>, <rc N>, <rd N> — and returns
//     -EINVAL for anything else, so an unknown tag is rejected, not ignored.
//     Only <b> is static: every other tag carries a jp_modifier func that rewrites
//     the template in place on each handshake initiation, which is the blast radius
//     of the upstream defects gate G6 tracks (tools/check-awg3-status.sh).
//     Optional; empty means none.
type AWGLocal struct {
	Jc, Jmin, Jmax     int
	I1, I2, I3, I4, I5 string
}

// AWGParams is the full obfuscation config for one AmneziaWG interface: the
// shared part (identical on both ends) plus this end's local part. AmneziaWG
// params live in the [Interface] section only — never in [Peer] — so this is
// attached to the interface (WGServerSpec), not to peers.
type AWGParams struct {
	Shared AWGShared
	Local  AWGLocal
}

// headerRanges returns H1-H4 in declaration order.
func (s AWGShared) headerRanges() [4]AWGHeader {
	return [4]AWGHeader{s.H1, s.H2, s.H3, s.H4}
}

// Validate enforces the official AmneziaWG parameter constraints. It returns a
// joined error describing every violation.
func (p AWGParams) Validate() error {
	var errs []error

	// Local: junk packets.
	if p.Local.Jc < awgJcMin || p.Local.Jc > awgJcMax {
		errs = append(errs, fmt.Errorf("Jc %d out of range [%d,%d]", p.Local.Jc, awgJcMin, awgJcMax))
	}
	if p.Local.Jmin < 0 || p.Local.Jmax > awgJMaxLimit {
		errs = append(errs, fmt.Errorf("Jmin/Jmax %d/%d out of range [0,%d]", p.Local.Jmin, p.Local.Jmax, awgJMaxLimit))
	}
	if p.Local.Jmin >= p.Local.Jmax {
		errs = append(errs, fmt.Errorf("Jmin (%d) must be < Jmax (%d)", p.Local.Jmin, p.Local.Jmax))
	}
	if floor := p.Shared.S4 + AWGJunkS4Margin; p.Local.Jmin < floor {
		errs = append(errs, fmt.Errorf("Jmin (%d) must be at least S4+%d (%d): a junk packet shorter than "+
			"the S4 the receiver strips underflows it", p.Local.Jmin, AWGJunkS4Margin, floor))
	}

	// Local: signature packets (hex blob or CPS template).
	for _, sig := range []struct{ name, value string }{
		{"I1", p.Local.I1}, {"I2", p.Local.I2}, {"I3", p.Local.I3},
		{"I4", p.Local.I4}, {"I5", p.Local.I5},
	} {
		if sig.value == "" {
			continue
		}
		if len(sig.value) >= awgStringMaxLen {
			errs = append(errs, fmt.Errorf("%s: length %d exceeds AWG string limit %d", sig.name, len(sig.value), awgStringMaxLen))
		}
		if !isCPSTemplate(sig.value) && !hexBlob.MatchString(sig.value) {
			errs = append(errs, fmt.Errorf("%s: must be a hex blob or CPS template, got %q", sig.name, sig.value))
		}
	}

	// Shared: junk-prefix sizes.
	if p.Shared.S1 < 0 || p.Shared.S1 > awgS1Limit {
		errs = append(errs, fmt.Errorf("S1 %d out of range [0,%d]", p.Shared.S1, awgS1Limit))
	}
	if p.Shared.S2 < 0 || p.Shared.S2 > awgS2Limit {
		errs = append(errs, fmt.Errorf("S2 %d out of range [0,%d]", p.Shared.S2, awgS2Limit))
	}
	if p.Shared.S3 < 0 || p.Shared.S3 > awgS3Limit {
		errs = append(errs, fmt.Errorf("S3 %d out of range [0,%d]", p.Shared.S3, awgS3Limit))
	}
	if p.Shared.S4 < 0 || p.Shared.S4 > awgS4Limit {
		errs = append(errs, fmt.Errorf("S4 %d out of range [0,%d]", p.Shared.S4, awgS4Limit))
	}
	// S1+56 ≠ S2 is a documented anti-detection recommendation (README/docs); the
	// kernel does NOT enforce it, but we do, so we never emit a fingerprint-able
	// size correlation between the init and response junk.
	if p.Shared.S1+56 == p.Shared.S2 {
		errs = append(errs, fmt.Errorf("S1+56 must not equal S2 (anti-detection): S1=%d S2=%d", p.Shared.S1, p.Shared.S2))
	}

	// Shared: header-type ranges must be well-formed and non-overlapping.
	errs = append(errs, validateHeaders(p.Shared.headerRanges())...)

	// Shared: the AmneziaWG 3.0 block, if the operator opted into it.
	errs = append(errs, p.Shared.validateAWG3()...)

	return errors.Join(errs...)
}

func validateHeaders(h [4]AWGHeader) []error {
	var errs []error
	names := [4]string{"H1", "H2", "H3", "H4"}
	for i, hdr := range h {
		if !hdr.valid() {
			errs = append(errs, fmt.Errorf("%s range %s is inverted (Min > Max)", names[i], hdr))
		}
	}
	// Check pairwise non-overlap by sorting on Min.
	type idx struct {
		h    AWGHeader
		name string
	}
	sorted := []idx{{h[0], "H1"}, {h[1], "H2"}, {h[2], "H3"}, {h[3], "H4"}}
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].h.Min < sorted[b].h.Min })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].h.overlaps(sorted[i].h) {
			errs = append(errs, fmt.Errorf("header ranges %s (%s) and %s (%s) overlap; H1-H4 must not overlap",
				sorted[i-1].name, sorted[i-1].h, sorted[i].name, sorted[i].h))
		}
	}
	return errs
}

// isCPSTemplate reports whether s uses AmneziaWG CPS tag syntax (contains '<').
func isCPSTemplate(s string) bool { return containsByte(s, '<') }

// userspaceTag matches the <c> (packet-counter) and <t> (timestamp) CPS tags,
// which the kernel module supports but the userspace WireGuard-Go implementation
// (mihomo proxies, Amnezia app clients) cannot parse.
var userspaceForbiddenTag = regexp.MustCompile(`<\s*[ct]\s*>`)

// ValidateUserspace is Validate plus the userspace restriction: I1-I5 must not
// use the <c> or <t> tags. Use this for AWG params destined for a userspace
// WireGuard implementation (mihomo wireguard proxies, Amnezia clients); the
// plain Validate is correct for kernel-module interfaces (awg-quick).
func (p AWGParams) ValidateUserspace() error {
	if err := p.Validate(); err != nil {
		return err
	}
	for _, sig := range []struct{ name, value string }{
		{"I1", p.Local.I1}, {"I2", p.Local.I2}, {"I3", p.Local.I3},
		{"I4", p.Local.I4}, {"I5", p.Local.I5},
	} {
		if userspaceForbiddenTag.MatchString(sig.value) {
			return fmt.Errorf("%s uses a <c>/<t> tag, which breaks userspace WireGuard-Go (use only <b>/<r>/<rc>/<rd>)", sig.name)
		}
	}
	// NOTE: S3/S4 (AmneziaWG 2.0 transport/cookie junk) ARE valid for userspace
	// amneziawg-go — but BOTH ends must run a 2.0-compatible AmneziaWG, or the
	// receiver crashes in handleTransport. That is a deployment/version requirement
	// (docs/onboarding.md), not something this validator can check.
	return nil
}
