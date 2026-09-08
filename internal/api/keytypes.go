package api

import "strings"

// Published-key types for PublishPublicKey (ADR-0025). The wire default (empty)
// is WireGuard, so an older agent that omits the field keeps publishing its WG
// key unchanged.
const (
	KeyTypeWireGuard = ""        // node's WireGuard public key (default)
	KeyTypeReality   = "reality" // exit's REALITY x25519 public key
	// KeyTypeClientVless is the master's CLIENT-FACING REALITY x25519 public key
	// (the client VLESS inbound). Distinct from KeyTypeReality, which is the exit's
	// master↔exit inbound key: a co-located controller+master node publishes both.
	// Free-form like the others, so it needs no proto/wire change of its own (the
	// wire bump to v4 is for the ClientVlessSpec on MasterSpec, not this key type).
	KeyTypeClientVless = "client-vless"

	// KeyTypeClientWG is the master's CLIENT-FACING WireGuard public key — the
	// identity of the AmneziaWG interface end users dial once the agent owns it
	// instead of wg-easy. Distinct from KeyTypeWireGuard, which is the node's
	// fleet-internal identity: these are two different interfaces on one host, and
	// the controller needs this one to render the .conf it hands a client.
	KeyTypeClientWG = "client-wg"

	// KeyTypeLifeline is the exit's LIFELINE interface WireGuard public key — the
	// reserve client-facing interface (awgl0) an exit may carry alongside its
	// master↔exit and ordinary client-facing identities. Rendered verbatim into
	// reserve client configs, so it needs the same validation as the other keys.
	KeyTypeLifeline = "lifeline"

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
