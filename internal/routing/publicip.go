package routing

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// DiscoverPublicIP reports the globally-routable address this host carries on the
// interface its default route leaves by, or "" when it has none.
//
// It exists because the node's public IP was only ever a FLAG. An agent started
// without --public-ip reported nothing, the store row stayed blank, and the
// console then filled the gap from the manifest — where the fallback was
// `ssh.host`. That is not the same fact: on a node whose direct path flaps, the
// operator points ssh at the mgmt overlay, and the console then displayed a
// ZeroTier address in a column labelled PUBLIC. Five of eight nodes in the
// reference fleet were in that state.
//
// The discovery is deliberately LOCAL. Asking an outside service what our address
// is would be the obvious implementation and the wrong one here: this fleet exists
// to move people through a censored network, and a periodic call to an
// echo-my-IP endpoint from every node is both a dependency that fails when it
// matters and a signal we have no reason to emit. The address is already on the
// interface; reading it costs one `ip route` and one `ip addr`.
//
// "" is returned rather than a guess whenever the answer is not certain: no
// default route, an unreadable interface, or an address that is not globally
// routable. A NAT'd host genuinely does not know its public address from the
// inside, and saying nothing leaves the operator's explicit value — the flag, or
// the manifest's public_ip — in charge, which is the correct authority there.
func DiscoverPublicIP(ctx context.Context) string {
	dev := defaultRouteDevice(ctx)
	if dev == "" {
		return ""
	}
	return globalAddrOn(ctx, dev)
}

// defaultRouteDevice returns the interface name the default route leaves by.
func defaultRouteDevice(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

// globalAddrOn returns the first globally-routable IPv4 address on dev.
func globalAddrOn(ctx context.Context, dev string) string {
	out, err := exec.CommandContext(ctx, "ip", "-4", "-brief", "addr", "show", "dev", dev).Output()
	if err != nil {
		return ""
	}
	return firstGlobalV4(string(out))
}

// firstGlobalV4 picks the first globally-routable address out of `ip -br addr`
// output. Split out from the exec so the classification is testable without a
// host to run on.
func firstGlobalV4(brief string) string {
	for _, line := range strings.Split(brief, "\n") {
		// `ip -br addr show dev X` prints: NAME STATE ADDR/LEN [ADDR/LEN ...]
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		for _, cidr := range fields[2:] {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			if addr := pfx.Addr(); isGlobalV4(addr) {
				return addr.String()
			}
		}
	}
	return ""
}

// isGlobalV4 reports whether addr is an IPv4 address the rest of the internet
// could route back to. Everything a VPS might carry alongside its public address
// — the mgmt overlay, a docker bridge, CGNAT behind a provider's NAT, a
// link-local autoconfiguration address — is excluded, because reporting one of
// those as "public" is the very confusion this function exists to end.
func isGlobalV4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	switch {
	case addr.IsPrivate(), // 10/8, 172.16/12, 192.168/16
		addr.IsLoopback(),
		addr.IsLinkLocalUnicast(), // 169.254/16
		addr.IsMulticast(),
		addr.IsUnspecified():
		return false
	}
	// 100.64.0.0/10 — carrier-grade NAT. Not private by Go's definition, and not
	// reachable from outside either.
	if cgnat := netip.MustParsePrefix("100.64.0.0/10"); cgnat.Contains(addr) {
		return false
	}
	return true
}

// FormatDiscovery renders what discovery found, for a log line the operator can
// act on. Kept beside the discovery so the two cannot drift.
func FormatDiscovery(found string) string {
	if found == "" {
		return "no globally-routable address on the default-route interface; " +
			"set agent --public-ip or the node's public_ip in the manifest"
	}
	return fmt.Sprintf("discovered public IP %s on the default-route interface", found)
}
