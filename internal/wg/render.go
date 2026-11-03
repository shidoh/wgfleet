package wg

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// RenderInput is everything needed to render one AmneziaWG interface config.
// PrivateKey is the node's secret, injected by the agent at render time; it is
// never supplied by the controller. AmneziaWG obfuscation comes from Spec.AWG
// (interface-level); when it is nil the result is a vanilla WireGuard config
// (used only for the external WARP/wgcf leg).
type RenderInput struct {
	Spec       domain.WGServerSpec
	Peers      []domain.PeerSpec
	PrivateKey string
}

// RenderInterface renders an awg-quick/wg-quick style config from in. It
// validates AmneziaWG parameters before emitting, so an invalid obfuscation set
// fails loudly rather than producing a config the kernel rejects.
// The MTU comes straight from the spec, which the controller computed along the
// tunnel chain — the renderer never invents one.
func RenderInterface(in RenderInput) (string, error) {
	if in.PrivateKey == "" {
		return "", fmt.Errorf("wg render: private key is required")
	}
	addr, err := interfaceAddress(in.Spec)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", in.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", addr)
	if in.Spec.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", in.Spec.ListenPort)
	}
	if in.Spec.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", in.Spec.MTU)
	}

	if in.Spec.AWG != nil {
		if err := in.Spec.AWG.Validate(); err != nil {
			return "", fmt.Errorf("wg render: %w", err)
		}
		writeAWG(&b, *in.Spec.AWG)
	}

	for _, p := range in.Peers {
		if err := writePeer(&b, p); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func writePeer(b *strings.Builder, p domain.PeerSpec) error {
	if p.PublicKey == "" {
		return fmt.Errorf("wg render: peer %q has no public key", p.Name)
	}
	if len(p.AllowedIPs) == 0 {
		return fmt.Errorf("wg render: peer %q has no AllowedIPs", p.Name)
	}
	b.WriteString("\n[Peer]\n")
	if p.Name != "" {
		fmt.Fprintf(b, "# %s\n", p.Name)
	}
	fmt.Fprintf(b, "PublicKey = %s\n", p.PublicKey)
	fmt.Fprintf(b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
	// Endpoint is emitted only when we dial the peer. An empty endpoint means the
	// peer dials us (the exit is the server side; the master initiates) — emitting
	// a bogus endpoint there would break the tunnel.
	if p.Endpoint != "" {
		fmt.Fprintf(b, "Endpoint = %s\n", p.Endpoint)
	}
	if p.Keepalive > 0 {
		fmt.Fprintf(b, "PersistentKeepalive = %d\n", p.Keepalive)
	}
	return nil
}

// writeAWG emits the AmneziaWG [Interface] obfuscation lines. Per the official
// rules every one of these belongs in [Interface], never in [Peer]. The local
// params (Jc/Jmin/Jmax, I1-I5) are this end's and may differ from the peer's;
// the shared params (S1-S4, H1-H4 ranges) must match. H ranges render as
// "min-max" (or a single value when Min==Max).
func writeAWG(b *strings.Builder, p domain.AWGParams) {
	// Local: junk packet counts/sizes.
	fmt.Fprintf(b, "Jc = %d\n", p.Local.Jc)
	fmt.Fprintf(b, "Jmin = %d\n", p.Local.Jmin)
	fmt.Fprintf(b, "Jmax = %d\n", p.Local.Jmax)

	// Shared: junk size prefixes.
	fmt.Fprintf(b, "S1 = %d\n", p.Shared.S1)
	fmt.Fprintf(b, "S2 = %d\n", p.Shared.S2)
	if p.Shared.S3 != 0 {
		fmt.Fprintf(b, "S3 = %d\n", p.Shared.S3)
	}
	if p.Shared.S4 != 0 {
		fmt.Fprintf(b, "S4 = %d\n", p.Shared.S4)
	}

	// Shared: header-type ranges.
	fmt.Fprintf(b, "H1 = %s\n", p.Shared.H1)
	fmt.Fprintf(b, "H2 = %s\n", p.Shared.H2)
	fmt.Fprintf(b, "H3 = %s\n", p.Shared.H3)
	fmt.Fprintf(b, "H4 = %s\n", p.Shared.H4)

	// Local: signature packets (optional).
	for i, v := range []string{p.Local.I1, p.Local.I2, p.Local.I3, p.Local.I4, p.Local.I5} {
		if v != "" {
			fmt.Fprintf(b, "I%d = %s\n", i+1, v)
		}
	}

	writeAWG3(b, p.Shared)
}

// writeAWG3 emits the AmneziaWG 3.0 [Interface] keys, each only when set. An
// absent key means "not configured" to amneziawg-tools, which is exactly the
// semantics a partial 3.0 opt-in needs; an empty VALUE, by contrast, is a parse
// error on the node.
//
// The spelling is load-bearing. The tools match keys case-insensitively but
// silently IGNORE a key they do not recognise — so a typo does not fail the
// render, it brings the interface up without header protection and says nothing.
// These names are taken from the tools' own config.c key table.
func writeAWG3(b *strings.Builder, s domain.AWGShared) {
	for _, kv := range []struct{ key, value string }{
		{"HeaderProtectionKey", s.HeaderProtectionKey},
		{"ContentPaddingAddition", s.ContentPaddingAddition},
		{"RekeyAfterTime", s.RekeyAfterTime},
		{"RekeyTimeout", s.RekeyTimeout},
		{"RejectAfterTime", s.RejectAfterTime},
		{"KeepaliveTimeout", s.KeepaliveTimeout},
		{"MaxHandshakeAttempts", s.MaxHandshakeAttempts},
	} {
		if kv.value != "" {
			fmt.Fprintf(b, "%s = %s\n", kv.key, kv.value)
		}
	}
	// A boolean in the tools: "on"/"off", nothing else (config.c parse_bool).
	if s.RandomTrailers {
		b.WriteString("RandomTrailers = on\n")
	}
}

// interfaceAddress renders the [Interface] Address as "ip/prefixlen", taking the
// prefix length from the address pool. When Spec.Address is empty it falls back
// to the first host of the pool.
func interfaceAddress(s domain.WGServerSpec) (string, error) {
	prefix, err := netip.ParsePrefix(s.AddressPool)
	if err != nil {
		return "", fmt.Errorf("wg render: parse address pool %q: %w", s.AddressPool, err)
	}
	addrStr := s.Address
	if addrStr == "" {
		first := prefix.Masked().Addr().Next()
		if !first.IsValid() || !prefix.Contains(first) {
			return "", fmt.Errorf("wg render: pool %q too small for an interface address", s.AddressPool)
		}
		addrStr = first.String()
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return "", fmt.Errorf("wg render: parse address %q: %w", addrStr, err)
	}
	return fmt.Sprintf("%s/%d", addr.String(), prefix.Bits()), nil
}

// HeaderProtectionKey belongs here as much as the other two: it is a chacha20 key
// whose entire purpose is that an observer does not have it, and writeAWG3 emits
// it into the same file. Plan output goes to terminals, CI logs and pasted bug
// reports.
var secretLine = regexp.MustCompile(`(?m)^(PrivateKey|PresharedKey|HeaderProtectionKey)\s*=\s*.*$`)

// RedactConfig masks secret key lines for safe display in dry-run output.
func RedactConfig(cfg string) string {
	return secretLine.ReplaceAllString(cfg, "$1 = <redacted>")
}
