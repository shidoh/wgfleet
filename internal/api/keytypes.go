package api

import "strings"

// Published-key types for PublishPublicKey (ADR-0025). The wire default (empty)
// is WireGuard, so an older agent that omits the field keeps publishing its WG
// key unchanged.
const (
	KeyTypeWireGuard = ""        // node's WireGuard public key (default)
	KeyTypeReality   = "reality" // exit's REALITY x25519 public key

	// KeyTypeWireGuardTunnelPrefix marks a PER-TUNNEL WireGuard public key
	// (ADR-0030): "wireguard:<exit-name>" is the master's dedicated identity for the
	// tunnel to that one exit, as opposed to the unsuffixed KeyTypeWireGuard, which
	// stays the node's single back-compat identity. The key_type field was already
	// free-form on the wire, so this needs no proto or wire-version change; a
	// controller that predates ADR-0030 rejects the unknown type with
	// InvalidArgument and the master keeps using its shared key.
	KeyTypeWireGuardTunnelPrefix = "wireguard:"
)

// TunnelKeyType builds the key_type for a per-tunnel WireGuard key.
func TunnelKeyType(tunnel string) string {
	return KeyTypeWireGuardTunnelPrefix + tunnel
}

// ParseTunnelKeyType splits a per-tunnel WireGuard key_type into its tunnel name.
// ok is false for every other key type, including a bare "wireguard:" with no
// tunnel — an empty tunnel name must not be mistaken for the shared identity.
func ParseTunnelKeyType(keyType string) (tunnel string, ok bool) {
	rest, found := strings.CutPrefix(keyType, KeyTypeWireGuardTunnelPrefix)
	if !found || rest == "" {
		return "", false
	}
	return rest, true
}
