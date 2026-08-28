package wg

import (
	"crypto/sha256"
	"encoding/binary"
)

// Keepalive bounds. WireGuard's own default is 25 s, chosen to sit under the ~30 s
// UDP mapping timeout common in consumer NAT. The band keeps that property — every
// value stays below 30 — while giving each tunnel end its own period.
//
// The gain is narrow and worth stating honestly, the same way ClientKeepaliveFor
// states it: any keepalive is a beacon, and moving off 25 does not hide it. What it
// removes is the CORRELATION. With one interval shared by the whole fleet, an idle
// tunnel emits a constant-size datagram on a 25.000-second period, and an observer
// who picks out one of our tunnels has a handle that joins it to every other — a
// shape that survives every payload obfuscation in this repository, which is
// precisely the passive-classification adversary ADR-0025 names.
const (
	keepaliveLowSeconds  = 15
	keepaliveHighSeconds = 28
)

// KeepaliveFor derives one tunnel end's persistent-keepalive period from a stable
// per-end identity.
//
// PersistentKeepalive is a LOCAL decision — it says how often THIS end sends its
// own keepalives — so the two ends of one tunnel may hold different values and an
// already-installed peer config keeps working unchanged. That is what makes this
// safe to roll: nothing has to be reissued, and no end has to agree with another.
//
// The draw must be stable for a given identity: a client's config is re-rendered
// from scratch on every portal visit, and a value that moved between renders would
// hand the same person a different config each time they opened their own link.
func KeepaliveFor(identity string) int {
	sum := sha256.Sum256([]byte("wgfleet|keepalive|v1|" + identity))
	span := uint32(keepaliveHighSeconds - keepaliveLowSeconds + 1)
	return keepaliveLowSeconds + int(binary.BigEndian.Uint32(sum[:4])%span)
}
