package domain

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// AmneziaWG 3.0 parameter model.
//
// Every 3.0 field lives on AWGShared rather than AWGLocal, and that is a
// deliberate safety choice rather than a claim about the protocol. Getting "must
// match" wrong breaks the tunnel; getting "may differ" wrong only costs a degree
// of freedom we have no use for. So all of them are shared until something proves
// otherwise, and only ONE of them is actually known to require it.
//
// Measured against a 3.1 kernel module with both ends rendered by the production
// renderers, against an UNMODIFIED AmneziaWG 2.0 peer:
//
//   - HeaderProtectionKey MUST match. A 2.0 peer gets no handshake at all. This is
//     the one parameter whose rollout is a flag day for every client.
//   - ContentPaddingAddition did NOT have to match: a padding server and a 2.0
//     peer passed traffic cleanly, including packets at the MTU edge. The likely
//     reason is that the inner IP header carries its own length, so a receiver
//     that knows nothing of the padding simply ignores the tail. It stays shared
//     anyway — we have no use for a per-end value, and this is one observation,
//     not a reading of the module's source.
//   - The timer ranges did not have to match either, which is what makes a staged
//     migration possible: see wg.WithAWG3Timers.
//
// The 3.0 timers are ranges, not scalars: the device redraws the value on every
// timer arm. That is the point of them — a fixed 25-second keepalive is a timing
// fingerprint that survives every payload-level obfuscation, which is the passive
// classification ADR-0025 names as the real adversary.
const (
	// headerProtectionKeyLen is HEADER_PROTECTION_KEY_SIZE in the kernel module
	// (= CHACHA_KEY_SIZE): header protection is chacha20 over the packet header.
	headerProtectionKeyLen = 32

	// headerProtectionMinPadding is the nonce length header protection reads from
	// the START of the Sx padding — S1 for handshake initiation, S2 for response,
	// S3 for cookie, S4 for transport. With a shorter pad the two ends derive
	// DIFFERENT nonces and every packet is dropped, while the interface stays UP.
	//
	// The module does reject S < 12, but only for values arriving in the SAME
	// setconf request: a config that sets HeaderProtectionKey and does not mention
	// S at all is accepted silently and the tunnel comes up dead. That is exactly
	// the path an operator takes when adding the key to a live interface, so this
	// check has to be ours.
	headerProtectionMinPadding = 12
)

// AWG3Enabled reports whether any AmneziaWG 3.0 parameter is set. The renderers
// use it to decide whether to emit the 3.0 block at all — mihomo's `version: 3`
// plus its v3-only keys, and the extra [Interface] keys in the exit's awg-quick
// config. Empty across the board means a pure AWG 2.0 interface, which is what
// every node renders until an operator opts in.
func (p AWGParams) AWG3Enabled() bool { return p.Shared.awg3Enabled() }

func (s AWGShared) awg3Enabled() bool {
	return s.HeaderProtectionKey != "" ||
		s.ContentPaddingAddition != "" ||
		s.RekeyAfterTime != "" ||
		s.RekeyTimeout != "" ||
		s.RejectAfterTime != "" ||
		s.KeepaliveTimeout != "" ||
		s.MaxHandshakeAttempts != ""
}

// WithoutAWG3Timers returns p with every AmneziaWG 3.0 timer cleared and
// everything else — header protection and content padding included — untouched.
//
// The timers are a property of the END that sets them, not of the tunnel: a peer
// on the defaults keeps working against one that randomises them. So a config
// handed to a client never carries them. Emitting them there would buy nothing
// and would turn a 2.0-compatible profile into one older apps refuse (mihomo's
// `version: 3`, timer keys in the .conf).
func (p AWGParams) WithoutAWG3Timers() AWGParams {
	p.Shared.RekeyAfterTime = ""
	p.Shared.RekeyTimeout = ""
	p.Shared.RejectAfterTime = ""
	p.Shared.KeepaliveTimeout = ""
	p.Shared.MaxHandshakeAttempts = ""
	return p
}

// validateAWG3 returns every AmneziaWG 3.0 violation in s. It is a no-op on a
// param set with no 3.0 fields, so AWG 2.0 interfaces are unaffected.
func (s AWGShared) validateAWG3() []error {
	if !s.awg3Enabled() {
		return nil
	}
	var errs []error

	if s.HeaderProtectionKey != "" {
		raw, err := base64.StdEncoding.DecodeString(s.HeaderProtectionKey)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("HeaderProtectionKey: not valid base64: %w", err))
		case len(raw) != headerProtectionKeyLen:
			errs = append(errs, fmt.Errorf("HeaderProtectionKey: decodes to %d bytes, must be exactly %d (chacha20 key)",
				len(raw), headerProtectionKeyLen))
		}
		// The S floor. Checked for all four independently so the message names the
		// one the operator actually has to fix.
		for _, f := range []struct {
			name  string
			value int
		}{{"S1", s.S1}, {"S2", s.S2}, {"S3", s.S3}, {"S4", s.S4}} {
			if f.value < headerProtectionMinPadding {
				errs = append(errs, fmt.Errorf(
					"%s = %d: with a HeaderProtectionKey set, S1-S4 must all be >= %d — the header-protection nonce is read from those bytes, and a shorter pad makes the two ends derive different nonces (the kernel accepts this silently and the tunnel comes up dead)",
					f.name, f.value, headerProtectionMinPadding))
			}
		}
	}

	for _, f := range []struct{ name, value string }{
		{"ContentPaddingAddition", s.ContentPaddingAddition},
		{"RekeyAfterTime", s.RekeyAfterTime},
		{"RekeyTimeout", s.RekeyTimeout},
		{"RejectAfterTime", s.RejectAfterTime},
		{"KeepaliveTimeout", s.KeepaliveTimeout},
		{"MaxHandshakeAttempts", s.MaxHandshakeAttempts},
	} {
		if f.value == "" {
			continue
		}
		if err := validAWGRange(f.value); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
		}
	}
	return errs
}

// validAWGRange checks the u16_range syntax AmneziaWG 3.0 uses for its tunable
// timers and padding: either a bare number or "min-max" with min <= max, both
// within u16. A malformed value is not merely rejected downstream — a typo that
// happens to parse as a scalar silently turns a randomised range back into a
// fixed timer, i.e. re-creates the fingerprint the range exists to remove.
func validAWGRange(v string) error {
	lo, hi, isRange := strings.Cut(v, "-")
	loN, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return fmt.Errorf("want a number or \"min-max\" within 0-65535, got %q", v)
	}
	if !isRange {
		return nil
	}
	hiN, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil {
		return fmt.Errorf("want a number or \"min-max\" within 0-65535, got %q", v)
	}
	if hiN < loN {
		return fmt.Errorf("range %q is inverted (max < min)", v)
	}
	return nil
}
