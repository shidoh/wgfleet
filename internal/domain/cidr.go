package domain

import (
	"fmt"
	"net/netip"
	"sort"
)

// CIDR arithmetic for the client routing table.
//
// A WireGuard client's AllowedIPs is a plain list — the protocol has no notion of
// "everything except". An operator who wants the private ranges to stay on the
// local network therefore needs that list EXPANDED, and expanding it by hand is
// exactly the kind of off-by-one arithmetic nobody should do twice.
//
// This is expansion, not policy: what to exclude and what to route back through
// the tunnel is written in the manifest by the operator. Nothing here decides
// which networks are "private" — that judgement is theirs, and the expanded
// result is shown in the plan and in the Web UI so it can be checked.

// ExpandAllowedIPs returns the client routing table for "the whole internet,
// except `exclude`, plus `routeThrough`".
//
// routeThrough is applied AFTER the subtraction, so a network listed there wins
// over a broader exclusion — `exclude: 172.16.0.0/12` with
// `routeThrough: 172.19.57.0/24` keeps that one subnet in the tunnel while
// the rest of the range stays local.
//
// An empty exclude list yields the single default route: with nothing subtracted
// there is nothing to expand, and 0.0.0.0/0 is what every WireGuard config means
// by "everything".
func ExpandAllowedIPs(exclude, routeThrough []string) ([]string, error) {
	if len(exclude) == 0 {
		return []string{"0.0.0.0/0"}, nil
	}
	cur := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, e := range exclude {
		p, err := parseV4Prefix("exclude_from_tunnel", e)
		if err != nil {
			return nil, err
		}
		var next []netip.Prefix
		for _, n := range cur {
			next = append(next, subtractPrefix(n, p)...)
		}
		cur = next
	}
	for _, r := range routeThrough {
		p, err := parseV4Prefix("route_through_cidrs", r)
		if err != nil {
			return nil, err
		}
		cur = append(cur, p)
	}
	cur = collapse(cur)

	out := make([]string, 0, len(cur))
	for _, p := range cur {
		out = append(out, p.String())
	}
	return out, nil
}

// parseV4Prefix accepts an IPv4 CIDR only. The data plane is IPv4-only, and an
// IPv6 entry here would silently do nothing rather than fail loudly.
func parseV4Prefix(field, s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s entry %q is not a valid CIDR: %w", field, s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s entry %q is IPv6; the data plane is IPv4-only", field, s)
	}
	return p.Masked(), nil
}

// subtractPrefix returns n with e removed, as the smallest set of prefixes that
// covers the remainder. It splits n in half and recurses only into the half that
// still overlaps e, which is what keeps the result minimal.
func subtractPrefix(n, e netip.Prefix) []netip.Prefix {
	switch {
	case !n.Overlaps(e):
		return []netip.Prefix{n}
	case n.Bits() >= e.Bits():
		// n lies entirely inside e (or is e): nothing survives.
		return nil
	}
	lo := netip.PrefixFrom(n.Addr(), n.Bits()+1)
	hi := netip.PrefixFrom(setBit(n.Addr(), n.Bits()), n.Bits()+1)
	return append(subtractPrefix(lo, e), subtractPrefix(hi, e)...)
}

// setBit returns addr with bit i (counted from the most significant) set.
func setBit(addr netip.Addr, i int) netip.Addr {
	b := addr.As4()
	b[i/8] |= 1 << (7 - uint(i%8))
	return netip.AddrFrom4(b)
}

// collapse sorts and merges the set: it drops prefixes contained in another and
// joins adjacent siblings, so the rendered list is both minimal and stable across
// renders (an unstable list would rewrite every client config on every pass).
func collapse(in []netip.Prefix) []netip.Prefix {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Addr() != in[j].Addr() {
			return in[i].Addr().Less(in[j].Addr())
		}
		return in[i].Bits() < in[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range in {
		if len(out) > 0 && contains(out[len(out)-1], p) {
			continue
		}
		out = append(out, p)
	}
	// Join siblings repeatedly: merging two /24s into a /23 can make that /23 the
	// sibling of another, so one pass is not enough.
	for merged := true; merged; {
		merged = false
		var next []netip.Prefix
		for i := 0; i < len(out); i++ {
			if i+1 < len(out) && siblings(out[i], out[i+1]) {
				next = append(next, netip.PrefixFrom(out[i].Addr(), out[i].Bits()-1))
				i++
				merged = true
				continue
			}
			next = append(next, out[i])
		}
		out = next
	}
	return out
}

func contains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// siblings reports whether a and b are the two halves of one prefix one bit shorter.
func siblings(a, b netip.Prefix) bool {
	if a.Bits() != b.Bits() || a.Bits() == 0 {
		return false
	}
	parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	return parent.Contains(b.Addr()) && a.Addr() == parent.Addr() && a.Addr() != b.Addr()
}
