package domain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
)

// Exit-initiated REALITY (ADR-0038). A filter on the RU path drops TCP the master
// opens to some exits after its first data segment, while flows the exit opens
// pass. In this mode the exit's xray runs as a reverse-proxy BRIDGE that dials
// every master's PORTAL (a VLESS+REALITY inbound on the master) and keeps
// multiplexed flows up; the master sends client streams down them.
//
// These are the first domain fields with json tags: the frozen golden specs are
// json.MarshalIndent(NodeSpec), and a nil pointer without omitempty would write
// "null" into every one of them. Tag every field added for this mode the same way.

// RealityPortalSocksPort is the port of the portal's SOCKS inbound that mihomo
// dials for an exit in this mode. Fixed (not on the wire in practice): the portal
// and mihomo are rendered by the same master agent.
const RealityPortalSocksPort = 10808

// RealityBridgeFingerprintDefault is the uTLS fingerprint the bridge presents to a
// portal when none is set: the one profile REALITY ≥ 26.9.8 admits with
// X25519MLKEM768 (see ClientVLESSFingerprintDefault).
const RealityBridgeFingerprintDefault = "chrome"

// ReverseTag is the xray reverse tag for a peer: the portal tags an exit's
// tunnel r-<exit>, the bridge tags a master's r-<master>.
func ReverseTag(peer string) string { return "r-" + peer }

// RealityBridgeSpec is the exit side of the mode: the masters whose portals the
// exit's xray dials. When set, the exit renders no REALITY inbound.
type RealityBridgeSpec struct {
	// Portals is one entry per master ready for the mode, ordered by slot.
	Portals []RealityPortalPeer `json:",omitempty"`
}

// RealityPortalPeer is one master's portal as the bridge dials it.
type RealityPortalPeer struct {
	// Master is the master's node name; it names the reverse tag r-<master>.
	Master string `json:",omitempty"`
	// Address is the portal's "ip:port" (a public IPv4 the exit can reach).
	Address string `json:",omitempty"`
	// PublicKey is the master's portal REALITY x25519 public key.
	PublicKey string `json:",omitempty"`
	// UUID is the VLESS id of this exit at this portal — a secret per
	// master+exit pair, distinct from the forward REALITY identity.
	UUID string `json:",omitempty"`
	// ShortID is the REALITY short-id (hex) of this exit at this portal.
	ShortID string `json:",omitempty"`
	// ServerName is the camouflage SNI the bridge sends.
	ServerName string `json:",omitempty"`
	// Fingerprint is the uTLS fingerprint; empty ⇒ chrome.
	Fingerprint string `json:",omitempty"`
}

// ResolvedFingerprint returns the bridge's uTLS fingerprint, chrome when unset.
func (p RealityPortalPeer) ResolvedFingerprint() string {
	if p.Fingerprint == "" {
		return RealityBridgeFingerprintDefault
	}
	return p.Fingerprint
}

// Validate checks the bridge invariants. It runs from the exit agent's planner,
// not NodeSpec.Validate, so a bad bridge never blocks the rest of the spec.
func (b RealityBridgeSpec) Validate() error {
	if len(b.Portals) == 0 {
		return errors.New("bridge has no portal to dial")
	}
	var errs []error
	seen := make(map[string]struct{}, len(b.Portals))
	for i, p := range b.Portals {
		if p.Master == "" {
			errs = append(errs, fmt.Errorf("portal[%d]: missing master", i))
		} else if _, dup := seen[p.Master]; dup {
			errs = append(errs, fmt.Errorf("duplicate portal for master %q", p.Master))
		}
		seen[p.Master] = struct{}{}
		if _, err := netip.ParseAddrPort(p.Address); err != nil {
			errs = append(errs, fmt.Errorf("portal[%d] (%s): address %q is not ip:port", i, p.Master, p.Address))
		}
		if p.PublicKey == "" {
			errs = append(errs, fmt.Errorf("portal[%d] (%s): missing public key", i, p.Master))
		}
		if p.UUID == "" {
			errs = append(errs, fmt.Errorf("portal[%d] (%s): missing UUID", i, p.Master))
		}
		if err := checkShortID(p.ShortID); err != nil {
			errs = append(errs, fmt.Errorf("portal[%d] (%s): %w", i, p.Master, err))
		}
		if p.ServerName == "" {
			errs = append(errs, fmt.Errorf("portal[%d] (%s): missing server name", i, p.Master))
		}
	}
	return errors.Join(errs...)
}

// RealityPortalSpec is the master side of the mode: a VLESS+REALITY inbound the
// bridges dial and a SOCKS inbound mihomo uses to reach each exit through them.
// The master generates the portal keypair locally; this spec carries no private
// key, and the SOCKS password is derived on the master and never on the wire.
type RealityPortalSpec struct {
	// ListenPort is the world-facing TCP port of the portal inbound.
	ListenPort int `json:",omitempty"`
	// SocksPort is the SOCKS inbound port; 0 ⇒ RealityPortalSocksPort.
	SocksPort int `json:",omitempty"`
	// ServerName is the camouflage SNI (REALITY serverNames[0]).
	ServerName string `json:",omitempty"`
	// Dest is the camouflage target "host:port"; it must support TLS 1.3 with
	// X25519MLKEM768 or the authorized handshake fails silently.
	Dest string `json:",omitempty"`
	// AllowIPv6 false ⇒ xray resolves IPv4 only (#20).
	AllowIPv6 bool `json:",omitempty"`
	// Image is the xray container image (pinned repo:tag).
	Image string `json:",omitempty"`
	// Clients is one bridge per exit in the mode that this master serves.
	Clients []RealityPortalClient `json:",omitempty"`
}

// RealityPortalClient is one exit's bridge as the portal admits it.
type RealityPortalClient struct {
	// Exit is the exit's node name: the SOCKS user and the reverse tag r-<exit>.
	Exit string `json:",omitempty"`
	// UUID matches the exit's RealityPortalPeer.UUID for this master.
	UUID string `json:",omitempty"`
	// ShortID matches the exit's RealityPortalPeer.ShortID for this master.
	ShortID string `json:",omitempty"`
}

// ResolvedSocksPort returns the SOCKS inbound port, the fixed default when unset.
func (s RealityPortalSpec) ResolvedSocksPort() int {
	if s.SocksPort > 0 {
		return s.SocksPort
	}
	return RealityPortalSocksPort
}

// Validate checks the portal invariants. It runs from the master agent's
// planner, not NodeSpec.Validate (as for ClientVLESS).
func (s RealityPortalSpec) Validate() error {
	var errs []error
	if s.ListenPort <= 0 || s.ListenPort > 65535 {
		errs = append(errs, fmt.Errorf("listen port %d out of range", s.ListenPort))
	}
	if s.SocksPort < 0 || s.SocksPort > 65535 {
		errs = append(errs, fmt.Errorf("socks port %d out of range", s.SocksPort))
	}
	if s.ServerName == "" {
		errs = append(errs, errors.New("server name (camouflage SNI) is required"))
	}
	if s.Dest == "" {
		errs = append(errs, errors.New("dest (camouflage host:port) is required"))
	}
	if s.Image == "" {
		errs = append(errs, errors.New("image is required"))
	}
	seen := make(map[string]struct{}, len(s.Clients))
	for i, c := range s.Clients {
		if c.Exit == "" {
			errs = append(errs, fmt.Errorf("client[%d]: missing exit", i))
		} else if _, dup := seen[c.Exit]; dup {
			errs = append(errs, fmt.Errorf("duplicate client for exit %q", c.Exit))
		}
		seen[c.Exit] = struct{}{}
		if c.UUID == "" {
			errs = append(errs, fmt.Errorf("client[%d] (%s): missing UUID", i, c.Exit))
		}
		if err := checkShortID(c.ShortID); err != nil {
			errs = append(errs, fmt.Errorf("client[%d] (%s): %w", i, c.Exit, err))
		}
	}
	return errors.Join(errs...)
}

// checkShortID requires a non-empty, even-length hex REALITY short-id of at most
// 16 digits. Empty is refused: the portal admits only issued ids.
func checkShortID(id string) error {
	if id == "" || len(id)%2 != 0 || len(id) > 16 {
		return fmt.Errorf("short-id %q must be 2-16 hex digits, even length", id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("short-id %q is not hex", id)
	}
	return nil
}
