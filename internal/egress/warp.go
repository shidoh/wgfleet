// Package egress renders egress-method configs for exit nodes. On MVP the only
// rendered egress is Cloudflare WARP via wgcf. The renderer enforces the two
// invariants that cost us real downtime by hand: Table = off (so
// wg-quick does not steal the default route and lock us out over SSH) and an
// explicit, computed MTU.
package egress

import (
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/wg"
)

// DefaultWARPEndpoint is Cloudflare's WARP endpoint.
const DefaultWARPEndpoint = "engage.cloudflareclient.com:2408"

// WARPKeepaliveSeconds is the PersistentKeepalive on the WARP peer. An exit
// reaching Cloudflare's anycast endpoint is effectively always behind NAT (a
// datacenter NAT, and the host NAT in nested/Lima runs), so without keepalive the
// tunnel's NAT mapping and handshake go cold whenever egress is idle — then the
// next packet pays a full re-handshake, which makes the warp-egress health probe
// time out and the node flap to Degraded. 25s is the standard WireGuard NAT-
// traversal interval and keeps the mapping and handshake hot.
const WARPKeepaliveSeconds = 25

// WARPConfig is the material needed to render a wgcf.conf. PrivateKey and the
// addresses come from `wgcf register` / `wgcf generate` on the node — each exit
// registers its own (one WARP private key per server). They are
// secrets and are redacted in dry-run output.
type WARPConfig struct {
	PrivateKey    string // WARP interface private key (secret)
	Address4      string // assigned WARP IPv4, e.g. "172.16.0.2/32"
	Address6      string // assigned WARP IPv6 (optional)
	PeerPublicKey string // Cloudflare WARP public key
	Endpoint      string // defaults to DefaultWARPEndpoint
	MTU           int    // computed along the tunnel chain; required
	DNS           string // optional resolver for the WARP interface
}

// RenderWGCF renders the wgcf.conf for a WARP egress. It refuses to render
// without an MTU (the value must be computed, never left to wg-quick's default)
// and always emits Table = off.
func RenderWGCF(c WARPConfig) (string, error) {
	if c.PrivateKey == "" {
		return "", fmt.Errorf("wgcf render: private key is required (run `wgcf register` first)")
	}
	if c.Address4 == "" {
		return "", fmt.Errorf("wgcf render: WARP IPv4 address is required")
	}
	if c.PeerPublicKey == "" {
		return "", fmt.Errorf("wgcf render: Cloudflare peer public key is required")
	}
	if c.MTU < wg.MinTunnelMTU {
		return "", fmt.Errorf("wgcf render: MTU %d must be computed and >= %d", c.MTU, wg.MinTunnelMTU)
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultWARPEndpoint
	}

	var b strings.Builder
	b.WriteString("# Rendered by wgfleet — WARP egress (wgcf). Do not edit by hand.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", c.Address4)
	if c.Address6 != "" {
		fmt.Fprintf(&b, "Address = %s\n", c.Address6)
	}
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	// CRITICAL: without Table = off, wg-quick installs a default
	// route through WARP and we lose SSH/management. Routing is done explicitly
	// by the routing reconciler instead.
	b.WriteString("Table = off\n")

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.PeerPublicKey)
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	b.WriteString("AllowedIPs = ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	// Keep the NAT mapping and handshake warm so idle egress does not let the
	// tunnel go cold (which flaps the warp-egress health check).
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", WARPKeepaliveSeconds)
	return b.String(), nil
}

// ParseWGCFProfile parses the wgcf-profile.conf produced by `wgcf generate` into
// the credential fields of a WARPConfig: the interface private key + assigned
// addresses and the Cloudflare peer's public key + endpoint. MTU/DNS/Table from
// the profile are intentionally ignored — the platform sets MTU itself and
// routes via policy routing with Table = off.
func ParseWGCFProfile(data []byte) (WARPConfig, error) {
	var c WARPConfig
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "PrivateKey":
			c.PrivateKey = val
		case "PublicKey":
			c.PeerPublicKey = val
		case "Endpoint":
			c.Endpoint = val
		case "Address":
			// Older wgcf writes one Address line per family, newer ones a single
			// comma-separated line.
			for _, a := range strings.Split(val, ",") {
				a = strings.TrimSpace(a)
				switch {
				case a == "":
				case strings.Contains(a, ":"):
					c.Address6 = a
				default:
					c.Address4 = a
				}
			}
		}
	}
	if c.PrivateKey == "" || c.Address4 == "" || c.PeerPublicKey == "" {
		return WARPConfig{}, fmt.Errorf("wgcf profile incomplete (private key/address4/peer key required)")
	}
	return c, nil
}
