//go:build linux

package health

import (
	"errors"
	"fmt"
	"syscall"
)

// probeAddr is the address the bind is attempted on: TEST-NET-1 (RFC 5737),
// guaranteed never to be a real destination — so this probe can never collide
// with traffic of its own.
//
// It stands in for "some server address a client dialled", which is what mihomo
// binds. That makes the answer exact for the case that matters and conservative
// for the other one: a WILDCARD holder (a kernel WireGuard interface) refuses
// every address on the port and is caught, while a holder bound to one address
// only refuses that address, so a port like :53 held by 127.0.0.53 reads as
// bindable — and it is, for every server a client will actually talk to.
// Measured on the stand: :443 refused, :53 allowed, on the same host.
var probeAddr = [4]byte{192, 0, 2, 1}

// UDPReturnBindable reports whether this network namespace can still open the
// transparent return socket mihomo's TPROXY path needs for a client flow whose
// destination port is `port`.
//
// It reproduces mihomo exactly (listener/tproxy/udp_linux.go `dialUDP`):
// SO_REUSEADDR + IP_TRANSPARENT, then bind to the SERVER's address:port. When the
// namespace already holds a wildcard socket on that port WITHOUT SO_REUSEADDR —
// which is what a kernel WireGuard interface is — the bind fails with EADDRINUSE
// and mihomo silently drops every reply packet on that port — every dropped reply
// lands on the client WG port, none on any other port.
//
// A false answer is a fact about this namespace, not an error. err is reserved for
// a probe that could not be taken at all (no CAP_NET_ADMIN, no socket), so a caller
// can tell "the path is blocked" from "I could not look" — the same distinction the
// drift probe draws with its `known` bool.
func UDPReturnBindable(port int) (bool, error) {
	if port <= 0 || port > 65535 {
		return false, fmt.Errorf("udp return probe: port %d out of range", port)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false, fmt.Errorf("udp return probe: socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return false, fmt.Errorf("udp return probe: SO_REUSEADDR: %w", err)
	}
	// IP_TRANSPARENT needs CAP_NET_ADMIN. The agent runs as root; a failure here is a
	// probe that could not be TAKEN, not a blocked port — reporting it as blocked
	// would make an unprivileged run look like an outage.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return false, fmt.Errorf("udp return probe: IP_TRANSPARENT: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port, Addr: probeAddr}); err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return false, nil
		}
		return false, fmt.Errorf("udp return probe: bind :%d: %w", port, err)
	}
	return true, nil
}
