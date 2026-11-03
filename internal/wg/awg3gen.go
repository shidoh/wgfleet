package wg

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// AmneziaWG 3.0 derivation bands.
//
// Only TWO timers are randomised: RekeyAfterTime and KeepaliveTimeout. Both are
// intervals an observer can read straight off the wire (a fixed 120-second rekey
// and a fixed 10-second passive keepalive are a timing signature that survives
// every payload-level obfuscation we apply), and both are per-end: a peer that
// runs the defaults keeps working against one that randomises them.
//
// RejectAfterTime, RekeyTimeout and MaxHandshakeAttempts are left UNSET, i.e. at
// the WireGuard defaults (180 s, 5 s, 18 attempts). The kernel module and the Go
// implementation treat those three differently (amneziawg kernel module issues
// #227 and #272: diverging semantics, and keys that can end up zeroed), so
// randomising them buys a little timing entropy at the price of an interop risk
// between our two backends. Not worth it.
//
// Every randomised timer keeps its WireGuard default as the LOWER bound and draws
// only the upper one, in a narrow band. That is what makes the ordering against
// the untouched defaults hold for every seed (TestWithAWG3TimerOrdering):
//
//   - RekeyAfterTime tops out at 140 s. WireGuard's receive-side refresh fires once
//     a session is older than RejectAfterTime − KeepaliveTimeout − RekeyTimeout,
//     which with our widest keepalive is 180 − 15 − 5 = 160 s; staying at or below
//     140 s keeps the scheduled rekey ahead of that path, and 40 s ahead of the
//     hard reject at 180 s.
//   - KeepaliveTimeout tops out at 15 s. It also sets how long a silent peer goes
//     unnoticed (KeepaliveTimeout + RekeyTimeout before a new handshake), so the
//     band stays close to the 10 s default rather than buying entropy with
//     slower dead-peer detection.
const (
	rekeyAfterLo    = 120
	rekeyAfterHiMin = 130
	rekeyAfterHiMax = 140

	keepaliveLo    = 10
	keepaliveHiMin = 12
	keepaliveHiMax = 15

	// defaultRejectAfterTime is WireGuard's REJECT_AFTER_TIME. We never set it; it
	// is here so the ordering test can hold the randomised rekey against it.
	defaultRejectAfterTime = 180
	// defaultRekeyTimeout is WireGuard's REKEY_TIMEOUT, likewise never set.
	defaultRekeyTimeout = 5

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
func WithAWG3(p domain.AWGParams, tunnelSeed, fleetSecret string) domain.AWGParams {
	return WithAWG3HeaderProtection(WithAWG3Timers(p, tunnelSeed), tunnelSeed, fleetSecret)
}

// WithAWG3Timers adds ONLY the 3.0 timer ranges — RekeyAfterTime and
// KeepaliveTimeout, nothing else (see the band comment above for why).
//
// The timers are a property of ONE end, not of the tunnel. Measured against a
// real 3.1 kernel module, a server running these timers keeps an UNMODIFIED
// AmneziaWG 2.0 peer working — handshake, traffic and repeated rekeys. So they
// belong in the render of the interface that sets them and nowhere else: the
// client leg puts them on the master's interface only, and every config handed
// to a client is stripped of them (domain.AWGParams.WithoutAWG3Timers). Header
// protection is the opposite case — it must match on both ends — which is why
// the two halves are separate functions.
func WithAWG3Timers(p domain.AWGParams, tunnelSeed string) domain.AWGParams {
	p.Shared.RekeyAfterTime = deriveRange(tunnelSeed, "rekey-after", rekeyAfterLo, rekeyAfterHiMin, rekeyAfterHiMax)
	p.Shared.KeepaliveTimeout = deriveRange(tunnelSeed, "keepalive", keepaliveLo, keepaliveHiMin, keepaliveHiMax)
	return p
}

// WithAWG3HeaderProtection adds ONLY the header-protection key: chacha20 over the
// packet header, and the one 3.0 parameter that is NOT backward compatible.
// Enabling it on a live interface disconnects every peer that does not carry the
// same key, so it belongs behind a deliberate operator decision rather than
// behind "turn on 3.x".
//
// It brings the rest of AmneziaWG 3.1's "Track B" with it, because every piece of
// it must match on both ends and the key already forces every peer to take a new
// config: random trailers, one padding size S for all four message types, and
// the stock header types 1-4. Upstream's 3.1 guidance is exactly this pairing —
// with trailers on and S1-S4 different, the receiver's classifier mistakes
// transport packets for handshakes and drops them (amneziawg-go #186, kernel
// module #226), and under header protection the type field is encrypted, so
// custom H ranges add nothing but classifier ambiguity.
func WithAWG3HeaderProtection(p domain.AWGParams, tunnelSeed, fleetSecret string) domain.AWGParams {
	p.Shared.HeaderProtectionKey = deriveHeaderProtectionKey(tunnelSeed, fleetSecret)
	p.Shared.RandomTrailers = true
	size := deriveTrackBPadding(tunnelSeed, fleetSecret)
	p.Local = shiftJunkForS4(p.Local, p.Shared.S4, size)
	p.Shared.S1, p.Shared.S2, p.Shared.S3, p.Shared.S4 = size, size, size, size
	for i, h := range []*domain.AWGHeader{&p.Shared.H1, &p.Shared.H2, &p.Shared.H3, &p.Shared.H4} {
		*h = domain.AWGHeader{Min: uint32(i + 1), Max: uint32(i + 1)}
	}
	return p
}

// Track B padding: one size for all four message types. At least the 12 bytes
// header protection reads its nonce from; at most 31, because S4 is prepended to
// every data packet and is paid for out of the MTU cushion; never 16, which puts
// transport sizes back on vanilla WireGuard's residue class modulo 16.
const (
	trackBPaddingLo = 12
	trackBPaddingHi = 31
)

// deriveTrackBPadding draws the padding from the fleet secret, not from the
// public salt alone: under Track B every message type carries the same S, so S
// is the one size a censor would otherwise compute from a node name.
func deriveTrackBPadding(seed, fleetSecret string) int {
	mac := hmac.New(sha256.New, []byte(fleetSecret))
	mac.Write([]byte(seed + "|awg3|padding"))
	sum := mac.Sum(nil)
	for i := 0; i+4 <= len(sum); i += 4 {
		size := int(mapU32(binary.BigEndian.Uint32(sum[i:i+4]), trackBPaddingLo, trackBPaddingHi))
		if size != 16 {
			return size
		}
	}
	return trackBPaddingLo + 5 // every draw was 16: 1 in 20^8, still deterministic
}

// shiftJunkForS4 moves this end's junk window by the change in S4, the same
// constant shift DeriveAWGParamsForEnd applies, so the window stays as far above
// the S4 a receiver strips as it was, and distinct draws stay distinct.
func shiftJunkForS4(local domain.AWGLocal, oldS4, newS4 int) domain.AWGLocal {
	shift := func(s4 int) int { return max(0, s4+junkS4Margin-jminLow) }
	d := shift(newS4) - shift(oldS4)
	local.Jmin += d
	local.Jmax += d
	return local
}

// deriveHeaderProtectionKey derives the 32-byte chacha20 key from the tunnel seed
// and returns it base64-encoded, which is the encoding both amneziawg-tools and
// mihomo accept (mihomo re-encodes it to hex for its own IPC).
// deriveHeaderProtectionKey derives the chacha20 key from a FLEET SECRET keyed by
// the tunnel seed.
//
// Every other derived AmneziaWG parameter — S1-S4, H1-H4, the junk window, the
// signature packets — is safe to derive from a public salt: they resist DPI
// through being non-default and per-tunnel, not through being unknown. Header
// protection is the one parameter where that reasoning does not hold. It is a
// chacha20 key whose entire purpose is that a passive observer cannot recognise
// or parse the header, and deriving it from a compiled-in constant plus a
// guessable node name reduced its strength to the entropy of the node name — in a
// repository intended to be published.
//
// HMAC rather than a plain hash of secret+seed: the secret is a key here, not
// another input, and HMAC is the construction that says so.
func deriveHeaderProtectionKey(seed, fleetSecret string) string {
	mac := hmac.New(sha256.New, []byte(fleetSecret))
	mac.Write([]byte(seed + "|awg3|header-protection-key"))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:headerProtectionKeyLen])
}

// deriveRange renders a u16 range "lo-hi" where lo is fixed at the protocol
// default and hi is drawn deterministically from [hiMin,hiMax]. Fixing lo is what
// keeps the cross-timer ordering safe for every possible seed.
func deriveRange(seed, label string, lo, hiMin, hiMax int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|awg3|%s", seed, label)))
	hi := int(mapU32(binary.BigEndian.Uint32(sum[:4]), uint32(hiMin), uint32(hiMax)))
	return fmt.Sprintf("%d-%d", lo, hi)
}
