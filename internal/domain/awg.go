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
//     project an earlier finding and the wg-easy table.
const (
	awgJcMin     = 1 // junk packet count: 1 ≤ Jc ≤ 128 (recommended 4-12)
	awgJcMax     = 128
	awgJMaxLimit = 1280 // Jmin < Jmax ≤ 1280 (kernel: Jmax < MESSAGE_MAX_SIZE)
	awgS1Limit   = 1132 // S1 ≤ 1132 (kernel: S1 + MESSAGE_INITIATION_SIZE ≤ MESSAGE_MAX_SIZE)
	awgS2Limit   = 1188 // S2 ≤ 1188 (kernel: S2 + MESSAGE_RESPONSE_SIZE ≤ MESSAGE_MAX_SIZE)

	// awgStringMaxLen mirrors the tools' MAX_AWG_STRING_LEN (5*1024) — the hard
	// cap config.c enforces on H and I string values.
	awgStringMaxLen = 5 * 1024
)

var hexBlob = regexp.MustCompile(`^(0x)?[0-9a-fA-F]*$`)

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
}

// AWGLocal holds the AmneziaWG parameters that MAY differ between the two ends
// of a tunnel — each end emits its own; the peer ignores them.
//
//   - Jc: number of junk packets sent after I1-I5 (1 ≤ Jc ≤ 128, recommended 4-12).
//   - Jmin/Jmax: junk packet size bounds (Jmin < Jmax ≤ 1280).
//   - I1-I5: signature packets imitating other protocols before the handshake;
//     hex blobs or CPS tag templates (<b ...>, <t>, <r N>, <rc N>, <rd N>).
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
	// S1+56 ≠ S2 is a documented anti-detection recommendation (README/docs); the
	// kernel does NOT enforce it, but we do, so we never emit a fingerprint-able
	// size correlation between the init and response junk.
	if p.Shared.S1+56 == p.Shared.S2 {
		errs = append(errs, fmt.Errorf("S1+56 must not equal S2 (anti-detection): S1=%d S2=%d", p.Shared.S1, p.Shared.S2))
	}

	// Shared: header-type ranges must be well-formed and non-overlapping.
	errs = append(errs, validateHeaders(p.Shared.headerRanges())...)

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
// (mihomo proxies, Amnezia app clients) cannot parse (the reference deployment §5/§9).
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
	return nil
}
