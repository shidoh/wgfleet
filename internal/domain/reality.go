package domain

// REALITY transport modes (ADR-0025). XHTTP wraps the tunnel in HTTP packet-up to
// dodge the foreign-DC volume-freeze; Vision is classic TCP + xtls-rprx-vision (the
// most battle-tested REALITY combo, no XHTTP layer). Empty ⇒ XHTTP (back-compat).
const (
	RealityModeXHTTP  = "xhttp"
	RealityModeVision = "vision"
)

// RealityServerSpec is the exit-side desired state for a VLESS+REALITY+XHTTP
// inbound (xray-core), rendered when TransportRealityXHTTP is enabled (ADR-0025).
//
// The exit generates its own REALITY x25519 keypair LOCALLY and publishes only
// the public key (keybroker principle #2 — the controller sees public keys only,
// never private). This spec therefore carries no private key; it holds the shared
// identifiers (controller-derived, IDENTICAL on both ends of the tunnel) and the
// camouflage parameters the inbound needs.
type RealityServerSpec struct {
	// ListenPort is the VLESS listen port (e.g. 443). It must differ from the
	// AWG awg0 port so both transports can run warm side by side.
	ListenPort int
	// UUID is the VLESS user id — MUST match the master's RealityTunnel.UUID.
	UUID string
	// ShortID is the REALITY short-id (hex) — MUST match the master.
	ShortID string
	// ServerName is the camouflage SNI (REALITY serverNames[0]).
	ServerName string
	// Dest is the camouflage target "host:port" the inbound borrows the
	// certificate of and falls back to for unauthenticated probes (REALITY
	// fallback-to-real-site — the documented anti-active-probing defense).
	Dest string
	// XHTTPPath is the XHTTP request path.
	XHTTPPath string
	// XHTTPMode is the XHTTP mode; "packet-up" splits the upstream into many
	// short POSTs and dodges the foreign-DC single-connection volume-freeze.
	XHTTPMode string
	// Mode is the REALITY transport mode (RealityModeXHTTP | RealityModeVision);
	// empty ⇒ XHTTP. Vision renders TCP + xtls-rprx-vision (no XHTTP layer).
	Mode string
	// AllowEmptySNI adds "" to the inbound serverNames so a ClientHello without an
	// SNI extension is accepted (the master then sends no SNI). Reported to bypass
	// the RU TSPU heuristic block (ADR-0025 / 2026 recon).
	AllowEmptySNI bool
	// AllowIPv6 false ⇒ the rendered config pins xray to IPv4 resolution
	// (dns.queryStrategy UseIPv4 + freedom domainStrategy UseIPv4), so an AAAA-only
	// dest does not black-hole the steal/egress on the IPv4-only data plane (#20).
	AllowIPv6 bool
	// Image is the xray container image (pinned repo:tag).
	Image string
}

// RealityTunnel is the master-side proxy descriptor for a REALITY/XHTTP exit
// (the mihomo `type: vless` proxy with reality-opts). The exit's REALITY public
// key is published by the exit; the shared identifiers are controller-derived and
// match the exit's RealityServerSpec. The endpoint host:port comes from the
// enclosing ExitTunnel.
type RealityTunnel struct {
	// UUID is the VLESS user id (shared with the exit's RealityServerSpec).
	UUID string
	// PublicKey is the exit's REALITY x25519 PUBLIC key (exit-generated), the
	// mihomo reality-opts.public-key.
	PublicKey string
	// ShortID is the REALITY short-id (hex), one of the server's shortIds.
	ShortID string
	// ServerName is the camouflage SNI the client sends (mihomo servername).
	ServerName string
	// Fingerprint is the client uTLS fingerprint (mihomo client-fingerprint,
	// e.g. "chrome", "firefox"). "none" ⇒ omit it (Go-default fingerprint).
	Fingerprint string
	// XHTTPPath is the XHTTP request path (must match the inbound).
	XHTTPPath string
	// XHTTPMode is the XHTTP mode (e.g. "packet-up"); set explicitly on both ends
	// because the auto+REALITY path has an xray bug (#5635).
	XHTTPMode string
	// Mode is the REALITY transport mode (RealityModeXHTTP | RealityModeVision),
	// matching the inbound; empty ⇒ XHTTP. Vision ⇒ network tcp + flow vision.
	Mode string
	// EmptySNI sends the ClientHello with no SNI (mihomo servername set to the exit
	// IP placeholder); the inbound must allow it (RealityServerSpec.AllowEmptySNI).
	EmptySNI bool
	// Mux enables XHTTP connection reuse (XMUX, xhttp-opts.reuse-settings) so the
	// REALITY handshake + dest-steal is amortized across requests instead of paid
	// per request. Client-side (mihomo) only; xray unchanged. Only the xhttp path
	// honours it (vision/TCP ignores it). See RealityTransportConfig.Mux.
	Mux bool
}
