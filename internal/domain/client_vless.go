package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ClientVLESSServerSpec is the master-side desired state for a CLIENT-FACING
// VLESS+REALITY+XHTTP inbound (xray-core) — an alternative client↔master
// transport for end users on paths where AmneziaWG is DPI-throttled (2026 RU
// recon; docs/research/2026-07-client-transport-dpi.md). It runs ALONGSIDE the
// client-facing AmneziaWG (WGServerSpec), not instead of it; users migrate as
// their AWG connection degrades.
//
// Unlike the exit-side RealityServerSpec (a single fleet-internal user), this
// inbound fronts MANY end users, each with its own VLESS credential (UUID +
// short-id) issued and revoked through the controller UI. The master generates
// its own REALITY x25519 keypair LOCALLY and publishes only the public key
// (keybroker principle #2 — the controller sees public keys only); this spec
// therefore carries no private key.
//
// Decrypted client traffic is forwarded to mihomo (the master's routing brain)
// over a loopback SOCKS hop, so VLESS clients get the SAME geo-routing /
// load-balance / exit selection / DNS as AWG clients — one data plane, not two.
type ClientVLESSServerSpec struct {
	// ListenPort is the TCP port the inbound listens on, world-facing. A high,
	// non-standard port evades the deep TLS inspection RU TSPU applies to 443
	// (2026 recon: 443 is inspected, high ports pass ~80%); the controller derives
	// a per-master default in [40000,60000] from the master name.
	ListenPort int
	// Clients is the set of issued, non-revoked VLESS credentials. Each end user
	// authenticates with its own UUID; a revoked user is simply absent here, so a
	// re-render drops it from the inbound's clients list.
	Clients []VLESSClient
	// ServerName is the camouflage SNI (REALITY serverNames[0]).
	ServerName string
	// Dest is the camouflage target "host:port" the inbound borrows the
	// certificate of and falls back to for unauthenticated probes. It MUST support
	// TLS 1.3 + X25519MLKEM768 or the authorized handshake fails silently (#22).
	Dest string
	// XHTTPPath is the XHTTP request path.
	XHTTPPath string
	// XHTTPMode is the XHTTP mode; "packet-up" splits the upstream into many short
	// POSTs. Empty ⇒ xray.DefaultXHTTPMode.
	XHTTPMode string
	// Fingerprint is the uTLS ClientHello fingerprint the client presents (vless://
	// `fp`, mihomo `client-fingerprint`). Empty ⇒ a stable, off-chrome default
	// (ClientVLESSFingerprintDefault): chrome is the fingerprint RU TSPU is reported
	// to flag under active blocking, so the client leg blends into a different real
	// browser instead — a STABLE choice (not per-connection randomized, which can
	// itself trip the freeze-under-changing-fingerprint heuristic). "none" ⇒ omit it
	// (the client's Go-default fingerprint), mirroring the exit realityProxy.
	Fingerprint string
	// Mux enables XHTTP connection reuse (XMUX, mihomo xhttp-opts.reuse-settings) in
	// the generated client profile: many streams ride one underlying XHTTP
	// connection, so the REALITY handshake + dest-steal is amortized instead of paid
	// per request. This is the strongest mitigation for the handshake-parallelism
	// volume-freeze RU TSPU applies to bursts of TLS handshakes to a foreign DC.
	// Client-side only (the xray inbound is unaffected) and honoured only in xhttp
	// mode (vision/TCP ignores it). Mirrors RealityTunnel.Mux.
	Mux bool
	// Mode is the REALITY transport mode (RealityModeXHTTP | RealityModeVision);
	// empty ⇒ XHTTP.
	Mode string
	// AllowEmptySNI adds "" to the inbound serverNames so a ClientHello without an
	// SNI extension is accepted. Reported as a strong RU-TSPU bypass (2026 recon,
	// empty-SNI lifted the block in 100% of one field test), so it defaults ON for
	// the client leg — clients then send no SNI.
	AllowEmptySNI bool
	// AllowIPv6 false ⇒ the rendered config pins xray to IPv4 resolution, so the
	// IPv4-only data plane never black-holes an AAAA-preferring client (#20).
	AllowIPv6 bool
	// SocksPort is the loopback port of the master's mihomo mixed/socks inbound the
	// xray outbound forwards decrypted client traffic to. Both ends use the same
	// value (agent-populated, ClientVLESSSocksPort); 0 ⇒ the default.
	SocksPort int
	// Image is the xray container image (pinned repo:tag).
	Image string
}

// VLESSClient is one issued end-user credential for the client-facing inbound.
// UUID is the VLESS user id; ShortID is this user's REALITY short-id.
//
// The UUID IS a credential: the REALITY public key is in every link and the
// inbound accepts the empty short-id, so a UUID plus the master's address is
// enough to connect. The controller stores it to build links and revoke access,
// but it must never leave through an unauthenticated surface — metrics, logs —
// which is what VLESSStatsID is for.
type VLESSClient struct {
	Name    string // operator-facing label, unique per master
	UUID    string // VLESS user id — secret, see above
	ShortID string // this user's REALITY short-id (hex, even length)
}

// VLESSStatsID is the non-secret identity of a VLESS credential: the first 12 hex
// digits of sha256(UUID). It is the xray user "email" the inbound counts traffic
// under, so per-client counters can be published on the agent's open /metrics
// and joined to a name on the controller without either side exposing the UUID.
func VLESSStatsID(uuid string) string {
	sum := sha256.Sum256([]byte(uuid))
	return hex.EncodeToString(sum[:])[:12]
}

// Validate checks the client-facing inbound invariants. It runs from
// NodeSpec.Validate when the master carries a ClientVLESS spec.
func (c ClientVLESSServerSpec) Validate() error {
	var errs []error
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		errs = append(errs, fmt.Errorf("listen port %d out of range", c.ListenPort))
	}
	if c.ServerName == "" {
		errs = append(errs, errors.New("server name (camouflage SNI) is required"))
	}
	if c.Dest == "" {
		errs = append(errs, errors.New("dest (camouflage host:port) is required"))
	}
	switch c.Mode {
	case "", RealityModeXHTTP, RealityModeVision:
	default:
		errs = append(errs, fmt.Errorf("unknown reality mode %q", c.Mode))
	}
	seen := make(map[string]struct{}, len(c.Clients))
	for i, cl := range c.Clients {
		if cl.UUID == "" {
			errs = append(errs, fmt.Errorf("client[%d] (%s): missing UUID", i, cl.Name))
		}
		if cl.Name == "" {
			errs = append(errs, fmt.Errorf("client[%d]: missing name", i))
			continue
		}
		if _, dup := seen[cl.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate client name %q", cl.Name))
		}
		seen[cl.Name] = struct{}{}
	}
	return errors.Join(errs...)
}

// Client-leg uTLS/XMUX defaults. The fingerprint is deliberately off "chrome" (the
// exit leg's default and the signature RU TSPU is reported to flag first) and STABLE
// (a per-connection randomized fingerprint can trip the freeze-under-change
// heuristic). Mux defaults ON because amortizing the REALITY handshake is the top
// handshake-parallelism-freeze mitigation. See config.ClientVLESSConfig for the
// operator override.
const (
	ClientVLESSFingerprintDefault = "firefox"
	ClientVLESSMuxDefault         = true
)

// ResolvedFingerprint returns the client uTLS fingerprint, defaulting an unset value
// to the off-chrome default.
func (c ClientVLESSServerSpec) ResolvedFingerprint() string {
	if c.Fingerprint == "" {
		return ClientVLESSFingerprintDefault
	}
	return c.Fingerprint
}

// ResolvedMux reports whether XMUX is on for the client profile. The spec field is a
// plain bool (keybroker resolves the operator tri-state); this exists so link/clash
// builders and tests read intent through one method.
func (c ClientVLESSServerSpec) ResolvedMux() bool { return c.Mux }

// ClientVLESSSocksPort is the master-loopback port the client-facing xray inbound
// forwards decrypted traffic to, where mihomo picks it up and applies the same
// routing as for AWG clients. Fixed (not on the wire): both the xray outbound and
// the mihomo mixed inbound render it, and it never leaves the host.
const ClientVLESSSocksPort = 7893

// ResolvedSocksPort returns the loopback SOCKS bridge port, falling back to the
// fixed default when unset.
func (c ClientVLESSServerSpec) ResolvedSocksPort() int {
	if c.SocksPort > 0 {
		return c.SocksPort
	}
	return ClientVLESSSocksPort
}
