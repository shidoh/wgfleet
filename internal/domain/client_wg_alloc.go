package domain

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrPoolExhausted reports that a master's client pool has no free address left.
// Callers surface it to the operator, who widens the pool or revokes something —
// silently reusing an address would put two clients on one tunnel address.
var ErrPoolExhausted = errors.New("client address pool exhausted")

// AllocateClientAddress picks the lowest free host address in pool, skipping the
// network and broadcast addresses, everything in reserved (the master's own
// address) and everything in taken (already-issued credentials). Both reserved
// and taken accept either form — "10.8.0.1" or "10.8.0.1/32" — because they come
// from two different sources: the interface spec and the store.
//
// The function is PURE: same arguments, same answer, no clock, no randomness, no
// store access. That is a hard requirement rather than a style preference. Under
// multi-master (ADR-0027) the write path replicates through raft and each replica
// applies the same log, so an allocation that depended on anything else would
// diverge between replicas. The leader therefore calls this BEFORE proposing the
// write and stores the concrete address it got back.
//
// Lowest-free (rather than next-after-highest) means a revoked credential's
// address is reused, so a long-lived master does not walk off the end of its pool
// through churn alone.
func AllocateClientAddress(pool string, reserved, taken []string) (string, error) {
	prefix, err := netip.ParsePrefix(pool)
	if err != nil {
		return "", fmt.Errorf("client address pool %q: %w", pool, err)
	}
	prefix = prefix.Masked()

	used := make(map[netip.Addr]struct{}, len(reserved)+len(taken))
	for _, group := range [][]string{reserved, taken} {
		for _, s := range group {
			addr, err := parseHostAddr(s)
			if err != nil {
				return "", err
			}
			used[addr] = struct{}{}
		}
	}

	// Start one past the network address; stop before the broadcast address. A
	// /31 or /32 pool therefore yields nothing, which is correct — it has no host
	// range to hand out.
	for addr := prefix.Addr().Next(); prefix.Contains(addr); addr = addr.Next() {
		if isBroadcast(prefix, addr) {
			break
		}
		if _, busy := used[addr]; busy {
			continue
		}
		return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
	}
	return "", fmt.Errorf("%s: %w", prefix, ErrPoolExhausted)
}

// parseHostAddr accepts a bare address or an address with a mask and returns the
// address itself, so callers may mix the two forms.
func parseHostAddr(s string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("client address %q: %w", s, err)
	}
	return p.Addr(), nil
}

// isBroadcast reports whether addr is the all-ones address of an IPv4 prefix.
// IPv6 has no broadcast address, so only v4 pools lose their last address.
func isBroadcast(prefix netip.Prefix, addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	last := prefix.Masked().Addr().As4()
	hostBits := addr.BitLen() - prefix.Bits()
	for i := range hostBits {
		last[3-i/8] |= 1 << (i % 8)
	}
	return addr.As4() == last
}
