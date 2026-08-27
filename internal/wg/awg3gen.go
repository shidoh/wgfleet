package wg

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// AmneziaWG 3.0 derivation bands.
//
// Every timer keeps its WireGuard default as the LOWER bound and randomises only
// the upper one. That is what makes the ordering invariant hold by construction
// rather than by luck: rekey always begins before the session is rejected,
// whatever the seed draws (TestWithAWG3TimerOrdering).
//
// Randomising the timers at all is the point of the 3.0 block for us. A fixed
// 25-second keepalive and a fixed 120-second rekey are a timing signature that
// survives every payload-level obfuscation we apply, and passive classification
// by traffic shape — not by fingerprint — is the adversary ADR-0025 names.
const (
	// Rekey starts at the WireGuard default of 120s; the upper bound stays well
	// below rejectAfterLo so a rekey always has room to complete.
	rekeyAfterLo    = 120
	rekeyAfterHiMin = 130
	rekeyAfterHiMax = 150

	// The session becomes unusable at the default 180s at the earliest — above
	// rekeyAfterHiMax by construction.
	rejectAfterLo    = 180
	rejectAfterHiMin = 190
	rejectAfterHiMax = 220

	rekeyTimeoutLo    = 5
	rekeyTimeoutHiMin = 6
	rekeyTimeoutHiMax = 9

	keepaliveLo    = 10
	keepaliveHiMin = 12
	keepaliveHiMax = 18

	// Left a scalar on purpose: the attempt COUNT is not observable on the wire the
	// way an interval is, so randomising it buys no obfuscation while making a
	// handshake-failure budget harder to reason about.
	maxHandshakeAttempts = 18

	// headerProtectionKeyLen mirrors HEADER_PROTECTION_KEY_SIZE (= CHACHA_KEY_SIZE)
	// in the kernel module: header protection is chacha20 over the packet header.
	headerProtectionKeyLen = 32
)

// WithAWG3 returns p with the AmneziaWG 3.0 block derived from tunnelSeed. The
// 2.0 params are carried through untouched, so this is a pure addition on top of
// DeriveAWGParamsForEnd.
//
// Like S1-S4 and H1-H4, every 3.0 field is SHARED and derived from the tunnel
// seed alone, so both ends compute byte-identical values with no coordination and
// nothing to store. The header-protection key in particular must match exactly:
// the two ends derive the same chacha20 state or every packet is dropped.
//
// The S1-S4 floor that header protection imposes (>= 12) needs no enforcement
// here — the 2.0 derivation already draws S1-S3 from [15,64] and S4 from [16,32],
// so it is satisfied by construction. TestWithAWG3AlwaysValidates keeps that true
// if those bands ever move.
//
// ContentPaddingAddition is deliberately NOT derived. It rides on every data
// packet exactly as S4 does, so a non-zero value eats the MTU cushion that
// AWGExtraOverhead sizes and black-holes full-size packets. Enabling
// it means folding it into the MTU chain first; until then, unset.
func WithAWG3(p domain.AWGParams, tunnelSeed string) domain.AWGParams {
	return WithAWG3HeaderProtection(WithAWG3Timers(p, tunnelSeed), tunnelSeed)
}

// WithAWG3Timers adds ONLY the 3.0 timer ranges. It is the half an operator can
// switch on without touching a single client.
//
// The split is not cosmetic. Measured against a real 3.1 kernel module with both
// ends rendered by the production renderers, a server running these timers keeps
// an UNMODIFIED AmneziaWG 2.0 peer working — handshake, traffic and repeated
// rekeys — while a server running header protection cuts that peer off outright.
// So the two halves have completely different costs: this one is free, the other
// one is a flag day on which every client must re-import. Bundling them, as this
// function used to, priced the free half at the expensive half's rate and was the
// reason the client leg stayed on 2.0.
//
// This is also the half that carries the anti-fingerprint value: a fixed
// 25-second keepalive and a fixed 120-second rekey are a timing signature that
// survives every payload-level obfuscation we apply.
func WithAWG3Timers(p domain.AWGParams, tunnelSeed string) domain.AWGParams {
	p.Shared.RekeyAfterTime = deriveRange(tunnelSeed, "rekey-after", rekeyAfterLo, rekeyAfterHiMin, rekeyAfterHiMax)
	p.Shared.RekeyTimeout = deriveRange(tunnelSeed, "rekey-timeout", rekeyTimeoutLo, rekeyTimeoutHiMin, rekeyTimeoutHiMax)
	p.Shared.RejectAfterTime = deriveRange(tunnelSeed, "reject-after", rejectAfterLo, rejectAfterHiMin, rejectAfterHiMax)
	p.Shared.KeepaliveTimeout = deriveRange(tunnelSeed, "keepalive", keepaliveLo, keepaliveHiMin, keepaliveHiMax)
	p.Shared.MaxHandshakeAttempts = fmt.Sprintf("%d", maxHandshakeAttempts)
	return p
}

// WithAWG3HeaderProtection adds ONLY the header-protection key: chacha20 over the
// packet header, and the one 3.0 parameter that is NOT backward compatible.
// Enabling it on a live interface disconnects every peer that does not carry the
// same key, so it belongs behind a deliberate operator decision rather than
// behind "turn on 3.x".
func WithAWG3HeaderProtection(p domain.AWGParams, tunnelSeed string) domain.AWGParams {
	p.Shared.HeaderProtectionKey = deriveHeaderProtectionKey(tunnelSeed)
	return p
}

// deriveHeaderProtectionKey derives the 32-byte chacha20 key from the tunnel seed
// and returns it base64-encoded, which is the encoding both amneziawg-tools and
// mihomo accept (mihomo re-encodes it to hex for its own IPC).
func deriveHeaderProtectionKey(seed string) string {
	sum := sha256.Sum256([]byte(seed + "|awg3|header-protection-key"))
	return base64.StdEncoding.EncodeToString(sum[:headerProtectionKeyLen])
}

// deriveRange renders a u16 range "lo-hi" where lo is fixed at the protocol
// default and hi is drawn deterministically from [hiMin,hiMax]. Fixing lo is what
// keeps the cross-timer ordering safe for every possible seed.
func deriveRange(seed, label string, lo, hiMin, hiMax int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|awg3|%s", seed, label)))
	hi := int(mapU32(binary.BigEndian.Uint32(sum[:4]), uint32(hiMin), uint32(hiMax)))
	return fmt.Sprintf("%d-%d", lo, hi)
}
