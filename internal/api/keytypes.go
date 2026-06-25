package api

// Published-key types for PublishPublicKey (ADR-0025). The wire default (empty)
// is WireGuard, so an older agent that omits the field keeps publishing its WG
// key unchanged.
const (
	KeyTypeWireGuard = ""        // node's WireGuard public key (default)
	KeyTypeReality   = "reality" // exit's REALITY x25519 public key
)
