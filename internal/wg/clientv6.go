package wg

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
)

// Client-facing IPv6, derived rather than configured.
//
// The data plane is IPv4-only on purpose — v6 forwarding is off, mihomo runs
// ipv6: false, and WARP's v6 egress is dead — so clients are handed 0.0.0.0/0 and
// nothing else. That closed an earlier finding's black hole and opened a quieter hole in
// its place: a phone with working carrier IPv6 keeps its native v6 route, and
// happy eyeballs prefers v6 to every dual-stack host worth naming, so Google,
// Cloudflare and most CDNs leave the tunnel entirely while the UI says "connected".
//
// The way out is not to carry v6 (that is a separate project) but to CLAIM it and
// refuse it audibly: give the client a ::/0 route into the tunnel so its own v6
// path is no longer preferred, and have the master answer with ICMPv6
// administratively-prohibited so the OS falls back to IPv4 in milliseconds instead
// of stalling on a silent drop. The difference between that and an earlier finding is
// exactly the ICMP.
//
// The prefix is DERIVED from the v4 pool rather than configured, because both ends
// have to agree on it and they are rendered by different components: the controller
// writes the client's config, the agent writes the interface. One pure function
// keeps them in step with no new wire field, no store column and no manifest key to
// get wrong.

// ClientULAFor derives the master's client-facing IPv6 /64 from its IPv4 client
// pool, as an RFC 4193 unique-local prefix: fd00::/8, a 40-bit global ID hashed
// from the pool, and a zero subnet.
//
// RFC 4193 asks for a randomly chosen global ID so two networks that meet do not
// collide. Hashing the pool is that randomness made reproducible: the value is
// unpredictable across fleets, stable for a given pool, and identical everywhere it
// is computed.
func ClientULAFor(v4Pool string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(v4Pool)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("client ULA: invalid IPv4 pool %q: %w", v4Pool, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("client ULA: %q is not an IPv4 pool", v4Pool)
	}
	sum := sha256.Sum256([]byte("wgfleet|client-ula|v1|" + p.Masked().String()))
	var b [16]byte
	b[0] = 0xfd
	copy(b[1:6], sum[:5]) // 40-bit global ID
	// bytes 6-7 are the subnet id, left zero; 8-15 are the interface id.
	return netip.PrefixFrom(netip.AddrFrom16(b), 64), nil
}

// ClientV6For places one client inside the derived /64 by carrying its IPv4 host
// bits into the low 32 bits of the address.
//
// Deriving the v6 address from the v4 one means the allocator stays untouched: the
// store still hands out a single IPv4 address per credential and there is exactly
// one place where "which address is this client" is decided. Two clients cannot
// collide in v6 without having already collided in v4, which UNIQUE(master, address)
// makes impossible.
func ClientV6For(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("client v6: invalid prefix %v", prefix)
	}
	if !v4.Is4() {
		return netip.Addr{}, fmt.Errorf("client v6: %v is not an IPv4 address", v4)
	}
	b := prefix.Addr().As16()
	v := v4.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b), nil
}
