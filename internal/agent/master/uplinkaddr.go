package master

import (
	"net"
	"net/netip"
)

// uplinkRouteProbe is any public IPv4 destination; only the route the kernel
// would pick for it matters. Connecting a UDP socket sends nothing.
const uplinkRouteProbe = "1.1.1.1:53"

// detectUplinkAddr is the IPv4 source address the master's own outbound traffic
// leaves with, as the kernel's main routing table picks it. That is the address
// the handshake counters watch: on a host with its public IP on the interface it
// is that IP, and behind a hoster's 1:1 NAT it is the private address the packets
// really carry. Zero when there is no IPv4 default route.
func detectUplinkAddr() netip.Addr {
	c, err := net.Dial("udp4", uplinkRouteProbe)
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}
	}
	a = a.Unmap()
	if !a.Is4() || a.IsLoopback() || a.IsUnspecified() {
		return netip.Addr{}
	}
	return a
}
