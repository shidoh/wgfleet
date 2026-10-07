package domain

// PerTunnelKeyPhase is one exit's position in the ADR-0030 migration from the
// master's single shared WireGuard identity to a dedicated per-tunnel one.
//
// WHY FOUR PHASES AND NOT TWO. The obvious "exit accepts both keys, then drop the
// old one" plan does not work as stated, because two WireGuard peers CANNOT share
// an allowed-IP. AllowedIPs is a routing trie keyed by address: configuring a
// second peer with the same master tunnel IP silently steals that /32 from the
// first, leaving the losing peer with no route for return traffic. Inbound packets
// still decrypt (receive-side crypto routing is by key), so the tunnel looks
// half-alive — handshakes succeed, replies black-hole. That is the exact
// failure mode this ADR exists to remove, so reproducing it during the migration
// would be perverse.
//
// The fix is that the per-tunnel identity gets its OWN address in the exit's pool
// (MasterTunnelHostIndex gives the pair: one host for the legacy peer, one for the new),
// so the two peers are disjoint in the trie and genuinely coexist. Given that,
// each phase moves exactly ONE side of the tunnel:
//
//	off    exit peers: [legacy@.2]            master dials: legacy@.2
//	dual   exit peers: [legacy@.2, new@.3]    master dials: legacy@.2   (exit-side only)
//	switch exit peers: [legacy@.2, new@.3]    master dials: new@.3      (master-side only)
//	on     exit peers: [new@.3]               master dials: new@.3      (exit-side only)
//
// Every transition is therefore reversible by reverting the manifest field: at
// `switch` the exit still accepts the legacy key, so backing out to `dual` restores
// the previous path with one mihomo restart and no exit-side change. Only the
// off→dual and on→(back) edges touch the exit, and neither disturbs the peer that
// is currently carrying traffic.
type PerTunnelKeyPhase string

const (
	// PerTunnelKeyOff is the pre-ADR-0030 behaviour and the default: the master
	// peers this exit with its single shared WireGuard identity.
	PerTunnelKeyOff PerTunnelKeyPhase = "off"
	// PerTunnelKeyDual pre-installs the per-tunnel peer on the exit while the master
	// keeps dialing with the legacy key. Additive and traffic-neutral — this is the
	// step that makes the later switch instant and rollback cheap.
	PerTunnelKeyDual PerTunnelKeyPhase = "dual"
	// PerTunnelKeySwitch flips the master onto the per-tunnel identity. The exit
	// still accepts the legacy key, so reverting to dual restores the old path.
	PerTunnelKeySwitch PerTunnelKeyPhase = "switch"
	// PerTunnelKeyOn drops the legacy peer from the exit. After this the shared
	// master key no longer opens this tunnel — the point of the whole exercise.
	PerTunnelKeyOn PerTunnelKeyPhase = "on"
)

// Valid reports whether p is a known phase.
func (p PerTunnelKeyPhase) Valid() bool {
	switch p {
	case PerTunnelKeyOff, PerTunnelKeyDual, PerTunnelKeySwitch, PerTunnelKeyOn:
		return true
	}
	return false
}

// MasterUsesPerTunnelKey reports whether the MASTER should dial this exit with its
// per-tunnel identity (and the per-tunnel tunnel IP) in this phase.
func (p PerTunnelKeyPhase) MasterUsesPerTunnelKey() bool {
	return p == PerTunnelKeySwitch || p == PerTunnelKeyOn
}

// ExitAcceptsLegacyKey reports whether the EXIT should still carry a peer for the
// master's shared identity in this phase.
func (p PerTunnelKeyPhase) ExitAcceptsLegacyKey() bool {
	return p != PerTunnelKeyOn
}

// ExitAcceptsPerTunnelKey reports whether the EXIT should carry a peer for the
// master's per-tunnel identity in this phase.
func (p PerTunnelKeyPhase) ExitAcceptsPerTunnelKey() bool {
	return p != PerTunnelKeyOff
}

// MaxMasterSlot is the highest master slot. Two hosts per slot plus the exit's own
// fit a /24 exit pool many times over; the bound exists so a typo cannot ask for
// host 20001.
const MaxMasterSlot = 63

// MasterTunnelHostIndex is where the master in slot lives inside an exit's address
// pool: one host for its legacy shared identity and one for its per-tunnel
// identity (ADR-0030). The exit is host 1.
//
// Two hosts per master, never shared between masters: WireGuard's AllowedIPs is a
// routing trie, so two peers claiming one /32 do not coexist — the second steals
// it and the first loses its return path while its handshakes keep succeeding.
// Slot 0 keeps hosts 2 and 3, which is what a one-master fleet has always used.
func MasterTunnelHostIndex(slot int) (legacy, perTunnel int) {
	return 2 + 2*slot, 3 + 2*slot
}
