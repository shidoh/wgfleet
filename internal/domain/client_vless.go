package domain

import (
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
// UUID is the VLESS user id; ShortID is this user's REALITY short-id. Neither is
// secret (the REALITY private key stays on the master), so the controller may
// store and enumerate them to build vless:// links and to revoke access.
type VLESSClient struct {
	Name    string // operator-facing label, unique per master
	UUID    string // VLESS user id
	ShortID string // this user's REALITY short-id (hex, even length)
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
